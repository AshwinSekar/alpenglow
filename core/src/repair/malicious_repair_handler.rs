use {
    super::{repair_handler::RepairHandler, repair_response::repair_response_packet_from_bytes},
    log::info,
    solana_clock::Slot,
    solana_entry::{
        block_component::{BlockComponent, BlockFooterV1, BlockHeaderV1, VersionedBlockMarker},
        entry::Entry,
    },
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::{
        blockstore::Blockstore,
        leader_schedule_cache::LeaderScheduleCache,
        shred::{Nonce, ProcessShredsStats, ReedSolomonCache, Shred, Shredder},
    },
    solana_perf::packet::Packet,
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    std::{
        collections::HashMap,
        net::SocketAddr,
        sync::{Arc, Mutex},
    },
};

#[derive(Clone, Debug, Default)]
pub struct MaliciousRepairConfig {
    /// If set, respond maliciously for slots where `slot % frequency == 0`
    pub bad_shred_slot_frequency: Option<Slot>,
    /// If set, respond maliciously for shred indices where `index % frequency == 0`
    pub bad_shred_index_frequency: Option<u64>,
    /// If set, generate a consistent but different block per requester.
    /// Each requester gets a unique version of the block that is consistently
    /// returned for all their requests for that slot.
    pub per_requester_equivocation: bool,
}

/// A cached equivocating block for a specific requester
struct CachedEquivocatingBlock {
    /// The 96 data shreds (header + entries + footer)
    shreds: Vec<Vec<u8>>,
}

pub struct MaliciousRepairHandler {
    blockstore: Arc<Blockstore>,
    keypair: Arc<Keypair>,
    leader_schedule_cache: Arc<LeaderScheduleCache>,
    config: MaliciousRepairConfig,
    reed_solomon_cache: ReedSolomonCache,
    /// Cache of generated equivocating blocks keyed by (slot, requester_pubkey)
    /// We use requester pubkey (derived from IP for now) to ensure consistent responses
    equivocating_blocks: Mutex<HashMap<(Slot, Pubkey), CachedEquivocatingBlock>>,
}

impl MaliciousRepairHandler {
    pub fn new(
        blockstore: Arc<Blockstore>,
        keypair: Arc<Keypair>,
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        config: MaliciousRepairConfig,
    ) -> Self {
        Self {
            blockstore,
            keypair,
            leader_schedule_cache,
            config,
            reed_solomon_cache: ReedSolomonCache::default(),
            equivocating_blocks: Mutex::new(HashMap::new()),
        }
    }

    /// Check if we should respond maliciously for this slot and shred index
    fn should_respond_maliciously(&self, slot: Slot, shred_index: u64) -> bool {
        let slot_matches = self
            .config
            .bad_shred_slot_frequency
            .is_some_and(|freq| slot % freq == 0);
        let index_matches = self
            .config
            .bad_shred_index_frequency
            .is_some_and(|freq| shred_index % freq == 0);

        // If both frequencies are set, both must match
        // If only one is set, that one must match
        match (
            self.config.bad_shred_slot_frequency,
            self.config.bad_shred_index_frequency,
        ) {
            (Some(_), Some(_)) => slot_matches && index_matches,
            (Some(_), None) => slot_matches,
            (None, Some(_)) => index_matches,
            (None, None) => false,
        }
    }

    /// Check if we were the leader for this slot
    fn is_leader_for_slot(&self, slot: Slot) -> bool {
        self.leader_schedule_cache
            .slot_leader_at(slot, None)
            .is_some_and(|leader| leader == self.keypair.pubkey())
    }

    /// Generate an equivocating shred - a legitimately signed shred with different data
    fn generate_equivocating_shred(
        &self,
        original_shred: &Shred,
        shred_index: u64,
    ) -> Option<Vec<u8>> {
        let slot = original_shred.slot();
        let parent_slot = original_shred.parent().ok()?;
        let version = original_shred.version();
        // Use 0 for reference_tick since we can't access the private method
        // This is fine for equivocation testing purposes
        let reference_tick = 0u8;

        // Create a shredder with the same slot parameters
        let shredder = Shredder::new(slot, parent_slot, reference_tick, version).ok()?;

        // Create fake entries with different data than the original
        // We use a unique hash based on the shred index to ensure different content
        let fake_hash = Hash::new_unique();
        let fake_entries = vec![Entry::new(&fake_hash, 1, vec![])];

        // Generate new shreds signed by our keypair
        let chained_merkle_root = original_shred.chained_merkle_root().ok();
        let is_last_in_slot = original_shred.last_in_slot();

        let shreds: Vec<Shred> = shredder
            .make_merkle_shreds_from_entries(
                &self.keypair,
                &fake_entries,
                is_last_in_slot,
                chained_merkle_root,
                shred_index as u32, // next_shred_index
                0,                  // next_code_index
                &self.reed_solomon_cache,
                &mut ProcessShredsStats::default(),
            )
            .collect();

        // Return the first data shred's payload
        shreds
            .into_iter()
            .find(|s| s.is_data())
            .map(|s| s.into_payload().to_vec())
    }

    /// Derive a "requester identity" from the socket address.
    /// In a real scenario we'd use the remote pubkey, but for testing
    /// we use a deterministic pubkey derived from the IP address.
    fn requester_identity(&self, addr: &SocketAddr) -> Pubkey {
        // Use the IP address bytes to create a deterministic pubkey
        let ip_bytes = match addr.ip() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let hash = solana_sha256_hasher::hash(&ip_bytes);
        Pubkey::new_from_array(hash.to_bytes())
    }

    /// Generate a full equivocating block (96 shreds) for a specific requester.
    /// The block is unique per requester but consistent across multiple requests.
    fn generate_equivocating_block(
        &self,
        slot: Slot,
        requester: Pubkey,
    ) -> Option<CachedEquivocatingBlock> {
        // Get the original block's parent info from blockstore
        let original_meta = self.blockstore.meta(slot).ok()??;
        let parent_slot = original_meta.parent_slot?;

        // Get the parent's block_id from the parent meta
        let parent_block_id = self
            .blockstore
            .get_parent_meta(slot, solana_ledger::blockstore_meta::BlockLocation::Original)
            .ok()
            .flatten()
            .map(|pm| pm.parent_block_id)
            .unwrap_or_else(Hash::default);

        // Create a unique chained merkle root based on the requester
        // This ensures different blocks for different requesters
        let unique_seed = solana_sha256_hasher::hashv(&[
            &slot.to_le_bytes(),
            requester.as_ref(),
            b"equivocation_seed",
        ]);
        let chained_merkle_root = Some(Hash::new_from_array(unique_seed.to_bytes()));

        let shredder = Shredder::new(slot, parent_slot, 0, 0).ok()?;
        let mut all_shreds = Vec::with_capacity(96);

        // 1. Create block header shreds (first 32 shreds, indices 0-31)
        let header = BlockHeaderV1 {
            parent_slot,
            parent_block_id,
        };
        let header_component =
            BlockComponent::new_block_marker(VersionedBlockMarker::new_block_header(header));

        let header_shreds: Vec<Shred> = shredder
            .make_merkle_shreds_from_component(
                &self.keypair,
                &header_component,
                false, // not last in slot
                chained_merkle_root,
                0,  // next_shred_index
                0,  // next_code_index
                &self.reed_solomon_cache,
                &mut ProcessShredsStats::default(),
            )
            .collect();

        // Get chained merkle root from header shreds for the next batch
        let header_merkle_root = header_shreds
            .iter()
            .find(|s| s.is_data())
            .and_then(|s| s.merkle_root().ok());

        for shred in header_shreds {
            if shred.is_data() {
                all_shreds.push(shred.into_payload().to_vec());
            }
        }

        // 2. Create entry shreds (next 32 shreds, indices 32-63)
        // Use unique content based on requester
        let unique_entry_hash = solana_sha256_hasher::hashv(&[
            &slot.to_le_bytes(),
            requester.as_ref(),
            b"entry_data",
        ]);
        let fake_entries = vec![Entry::new(
            &Hash::new_from_array(unique_entry_hash.to_bytes()),
            1,
            vec![],
        )];

        let entry_shreds: Vec<Shred> = shredder
            .make_merkle_shreds_from_entries(
                &self.keypair,
                &fake_entries,
                false, // not last in slot
                header_merkle_root,
                32, // next_shred_index
                32, // next_code_index
                &self.reed_solomon_cache,
                &mut ProcessShredsStats::default(),
            )
            .collect();

        let entry_merkle_root = entry_shreds
            .iter()
            .find(|s| s.is_data())
            .and_then(|s| s.merkle_root().ok());

        for shred in entry_shreds {
            if shred.is_data() {
                all_shreds.push(shred.into_payload().to_vec());
            }
        }

        // 3. Create block footer shreds (last 32 shreds, indices 64-95)
        let footer = BlockFooterV1 {
            bank_hash: Hash::default(),
            block_producer_time_nanos: 0,
            block_user_agent: vec![],
            final_cert: None,
            skip_reward_cert: None,
            notar_reward_cert: None,
        };
        let footer_component =
            BlockComponent::new_block_marker(VersionedBlockMarker::new_block_footer(footer));

        let footer_shreds: Vec<Shred> = shredder
            .make_merkle_shreds_from_component(
                &self.keypair,
                &footer_component,
                true, // last in slot
                entry_merkle_root,
                64, // next_shred_index
                64, // next_code_index
                &self.reed_solomon_cache,
                &mut ProcessShredsStats::default(),
            )
            .collect();

        for shred in footer_shreds {
            if shred.is_data() {
                all_shreds.push(shred.into_payload().to_vec());
            }
        }

        info!(
            "Generated equivocating block for slot {} requester {:?} with {} shreds",
            slot,
            requester,
            all_shreds.len()
        );

        Some(CachedEquivocatingBlock { shreds: all_shreds })
    }

    /// Get a specific shred from the equivocating block for this requester
    fn get_equivocating_shred(
        &self,
        slot: Slot,
        shred_index: u64,
        requester: Pubkey,
    ) -> Option<Vec<u8>> {
        let mut cache = self.equivocating_blocks.lock().unwrap();

        // Check if we already have a block for this requester
        if !cache.contains_key(&(slot, requester)) {
            // Generate a new block for this requester
            if let Some(block) = self.generate_equivocating_block(slot, requester) {
                cache.insert((slot, requester), block);
            }
        }

        cache
            .get(&(slot, requester))
            .and_then(|block| block.shreds.get(shred_index as usize).cloned())
    }
}

impl RepairHandler for MaliciousRepairHandler {
    fn blockstore(&self) -> &Blockstore {
        &self.blockstore
    }

    fn repair_response_packet(
        &self,
        slot: Slot,
        shred_index: u64,
        block_id: Option<Hash>,
        dest: &SocketAddr,
        nonce: Nonce,
    ) -> Option<Packet> {
        // Handle per-requester equivocation mode
        if self.config.per_requester_equivocation
            && block_id.is_none()
            && self.is_leader_for_slot(slot)
            && self.should_respond_maliciously(slot, shred_index)
        {
            let requester = self.requester_identity(dest);
            if let Some(shred_bytes) = self.get_equivocating_shred(slot, shred_index, requester) {
                info!(
                    "Responding with per-requester equivocating shred slot {} index {} to {}",
                    slot, shred_index, dest
                );
                return repair_response_packet_from_bytes(shred_bytes, dest, nonce);
            }
        }

        // Get the original shred from blockstore
        let original_shred_bytes = match block_id {
            None => self.blockstore.get_data_shred(slot, shred_index),
            Some(block_id) => {
                let location = self.blockstore().get_block_location(slot, block_id)?;
                self.blockstore()
                    .get_data_shred_from_location(slot, shred_index, location)
            }
        }
        .expect("Blockstore could not get data shred")?;

        // Handle legacy per-shred equivocation mode
        if block_id.is_none()
            && self.is_leader_for_slot(slot)
            && self.should_respond_maliciously(slot, shred_index)
            && !self.config.per_requester_equivocation
        {
            // Parse the original shred to get its metadata
            if let Ok(original_shred) =
                Shred::new_from_serialized_shred(original_shred_bytes.clone())
            {
                if let Some(equivocating_shred) =
                    self.generate_equivocating_shred(&original_shred, shred_index)
                {
                    info!(
                        "Responding with equivocating shred in slot {slot} index {shred_index} to \
                         {dest}"
                    );
                    return repair_response_packet_from_bytes(equivocating_shred, dest, nonce);
                }
            }
        }

        // Fall back to normal response
        repair_response_packet_from_bytes(original_shred_bytes, dest, nonce)
    }
}
