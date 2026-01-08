use {
    crate::{
        repair::{
            outstanding_requests::OutstandingRequests,
            packet_threshold::DynamicPacketToProcessThreshold,
            repair_service::RepairInfo,
            serve_repair::{BlockIdRepairResponse, BlockIdRepairType},
        },
    },
    crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender},
    dashmap::{mapref::entry::Entry::Occupied, DashMap},
    solana_clock::Slot,
    solana_gossip::cluster_info::ClusterInfo,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::blockstore::Blockstore,
    solana_perf::{
        packet::{PacketBatch, PacketRef},
        recycler::Recycler,
    },
    solana_streamer::streamer::{self, PacketBatchReceiver, StreamerReceiveStats},
    solana_votor_messages::migration::MigrationStatus,
    std::{
        net::UdpSocket,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

pub const MAX_BLOCK_ID_REQUESTS_PER_SECOND: usize = 10;

pub type BlockIdRepairRequestSender = Sender<BlockIdRepairRequest>;
pub type BlockIdRepairRequestReceiver = Receiver<BlockIdRepairRequest>;

type RetryableRequestsSender = Sender<BlockIdRepairRequest>;
type RetryableRequestsReceiver = Receiver<BlockIdRepairRequest>;
type OutstandingBlockIdRepairs = OutstandingRequests<BlockIdRepairType>;

#[derive(Debug, Clone)]
pub struct BlockIdRepairRequest {
    pub slot: Slot,
    pub block_id: Hash,
    pub repair_type: BlockIdRepairType,
}

#[derive(Default)]
struct BlockIdRepairResponsesStats {
    total_packets: usize,
    processed: usize,
    dropped_packets: usize,
    invalid_packets: usize,
    parent_fec_set_count_responses: usize,
    fec_set_root_responses: usize,
}

impl BlockIdRepairResponsesStats {
    fn report(&mut self) {
        datapoint_info!(
            "block_id_repair_responses",
            ("total_packets", self.total_packets, i64),
            ("processed", self.processed, i64),
            ("dropped_packets", self.dropped_packets, i64),
            ("invalid_packets", self.invalid_packets, i64),
            (
                "parent_fec_set_count_responses",
                self.parent_fec_set_count_responses,
                i64
            ),
            ("fec_set_root_responses", self.fec_set_root_responses, i64),
        );
        *self = Self::default();
    }
}

struct BlockIdRepairRequestsStats {
    total_requests: usize,
    parent_fec_set_count_requests: usize,
    fec_set_root_requests: usize,
    last_report: Instant,
}

impl Default for BlockIdRepairRequestsStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            parent_fec_set_count_requests: 0,
            fec_set_root_requests: 0,
            last_report: Instant::now(),
        }
    }
}

impl BlockIdRepairRequestsStats {
    fn report(&mut self) {
        if self.last_report.elapsed().as_secs() > 2 && self.total_requests > 0 {
            datapoint_info!(
                "block_id_repair_requests",
                ("total_requests", self.total_requests, i64),
                (
                    "parent_fec_set_count_requests",
                    self.parent_fec_set_count_requests,
                    i64
                ),
                ("fec_set_root_requests", self.fec_set_root_requests, i64),
            );
            *self = Self::default();
        }
    }
}

pub struct BlockIdRepairChannels {
    pub block_id_repair_request_receiver: BlockIdRepairRequestReceiver,
}

pub struct BlockIdRepairService {
    thread_hdls: Vec<JoinHandle<()>>,
}

impl BlockIdRepairService {
    pub fn new(
        exit: Arc<AtomicBool>,
        blockstore: Arc<Blockstore>,
        block_id_repair_socket: Arc<UdpSocket>,
        block_id_repair_channels: BlockIdRepairChannels,
        repair_info: RepairInfo,
        migration_status: Arc<MigrationStatus>,
    ) -> Self {
        let outstanding_requests = Arc::<RwLock<OutstandingBlockIdRepairs>>::default();
        let (response_sender, response_receiver) = unbounded();

        let BlockIdRepairChannels {
            block_id_repair_request_receiver,
        } = block_id_repair_channels;

        // UDP receiver thread
        let t_receiver = streamer::receiver(
            "solRcvrBlockId".to_string(),
            block_id_repair_socket.clone(),
            exit.clone(),
            response_sender.clone(),
            Recycler::default(),
            Arc::new(StreamerReceiveStats::new(
                "block_id_repair_response_receiver",
            )),
            Some(Duration::from_millis(1)), // coalesce
            false,                          // use_pinned_memory
            None,                           // in_vote_only_mode
            false,                          // is_staked_service
        );

        let block_id_request_statuses: Arc<DashMap<(Slot, Hash), Instant>> =
            Arc::new(DashMap::new());
        let (retryable_requests_sender, retryable_requests_receiver) = unbounded();

        // Listen for responses to our block ID repair requests
        let t_block_id_responses = Self::run_responses_listener(
            block_id_request_statuses.clone(),
            response_receiver,
            blockstore.clone(),
            outstanding_requests.clone(),
            exit.clone(),
            retryable_requests_sender,
            repair_info.cluster_info.clone(),
            migration_status.clone(),
        );

        // Process block ID repair requests
        let t_block_id_requests = Self::run_process_block_id_requests(
            block_id_request_statuses,
            block_id_repair_request_receiver,
            retryable_requests_receiver,
            block_id_repair_socket,
            repair_info,
            outstanding_requests,
            exit,
            migration_status,
        );

        Self {
            thread_hdls: vec![t_receiver, t_block_id_responses, t_block_id_requests],
        }
    }

    fn run_responses_listener(
        block_id_request_statuses: Arc<DashMap<(Slot, Hash), Instant>>,
        response_receiver: PacketBatchReceiver,
        blockstore: Arc<Blockstore>,
        outstanding_requests: Arc<RwLock<OutstandingBlockIdRepairs>>,
        exit: Arc<AtomicBool>,
        retryable_requests_sender: RetryableRequestsSender,
        cluster_info: Arc<ClusterInfo>,
        migration_status: Arc<MigrationStatus>,
    ) -> JoinHandle<()> {
        Builder::new()
            .name("solBlockIdRepResp".to_string())
            .spawn(move || {
                let mut stats = BlockIdRepairResponsesStats::default();
                let mut last_stats_report = Instant::now();

                while !exit.load(Ordering::Relaxed) {
                    let timeout = Duration::from_millis(200);
                    let response_packet_batches = match response_receiver.recv_timeout(timeout) {
                        Ok(batch) => batch,
                        Err(RecvTimeoutError::Timeout) => {
                            if last_stats_report.elapsed().as_secs() >= 10 {
                                stats.report();
                                last_stats_report = Instant::now();
                            }
                            continue;
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    };

                    Self::process_block_id_repair_responses(
                        &block_id_request_statuses,
                        std::slice::from_ref(&response_packet_batches),
                        &blockstore,
                        &outstanding_requests,
                        &mut stats,
                        &retryable_requests_sender,
                        &cluster_info.keypair(),
                        &migration_status,
                    );
                }
            })
            .unwrap()
    }

    fn run_process_block_id_requests(
        block_id_request_statuses: Arc<DashMap<(Slot, Hash), Instant>>,
        block_id_repair_request_receiver: BlockIdRepairRequestReceiver,
        retryable_requests_receiver: RetryableRequestsReceiver,
        block_id_repair_socket: Arc<UdpSocket>,
        repair_info: RepairInfo,
        outstanding_requests: Arc<RwLock<OutstandingBlockIdRepairs>>,
        exit: Arc<AtomicBool>,
        migration_status: Arc<MigrationStatus>,
    ) -> JoinHandle<()> {
        Builder::new()
            .name("solBlockIdRepReq".to_string())
            .spawn(move || {
                let mut last_stats_report = Instant::now();
                let mut stats = BlockIdRepairRequestsStats::default();
                let mut request_throttle = DynamicPacketToProcessThreshold::default();

                while !exit.load(Ordering::Relaxed) {
                    // Handle new requests
                    let timeout = Duration::from_millis(100);
                    match block_id_repair_request_receiver.recv_timeout(timeout) {
                        Ok(request) => {
                            Self::process_block_id_request(
                                &request,
                                &block_id_request_statuses,
                                &block_id_repair_socket,
                                &repair_info,
                                &outstanding_requests,
                                &mut stats,
                                &mut request_throttle,
                                &migration_status,
                            );
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            // Also process any retryable requests
                            if let Ok(request) = retryable_requests_receiver.try_recv() {
                                Self::process_block_id_request(
                                    &request,
                                    &block_id_request_statuses,
                                    &block_id_repair_socket,
                                    &repair_info,
                                    &outstanding_requests,
                                    &mut stats,
                                    &mut request_throttle,
                                    &migration_status,
                                );
                            }
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    }

                    if last_stats_report.elapsed().as_secs() >= 10 {
                        stats.report();
                        last_stats_report = Instant::now();
                    }
                }
            })
            .unwrap()
    }

    fn process_block_id_request(
        request: &BlockIdRepairRequest,
        block_id_request_statuses: &DashMap<(Slot, Hash), Instant>,
        _block_id_repair_socket: &UdpSocket,
        _repair_info: &RepairInfo,
        _outstanding_requests: &RwLock<OutstandingBlockIdRepairs>,
        stats: &mut BlockIdRepairRequestsStats,
        request_throttle: &mut DynamicPacketToProcessThreshold,
        _migration_status: &MigrationStatus,
    ) {
        // Check throttle
        if !request_throttle.should_drop(stats.total_requests) {
            return;
        }

        // Check if already requested recently
        let key = (request.slot, request.block_id);
        if let Occupied(entry) = block_id_request_statuses.entry(key) {
            if entry.get().elapsed() < Duration::from_secs(5) {
                return; // Skip if requested within last 5 seconds
            }
            entry.remove();
        }

        // Record that we're making this request
        block_id_request_statuses.insert(key, Instant::now());
        stats.total_requests += 1;

        match &request.repair_type {
            BlockIdRepairType::ParentAndFecSetCount { .. } => {
                stats.parent_fec_set_count_requests += 1;
            }
            BlockIdRepairType::FecSetRoot { .. } => {
                stats.fec_set_root_requests += 1;
            }
        }

        // Send the request (implementation would go here)
        // This would use serve_repair to send the actual request
        // For now, we'll leave this as a placeholder
        warn!(
            "Block ID repair request sending not yet implemented: {:?}",
            request
        );
    }

    fn process_block_id_repair_responses(
        _block_id_request_statuses: &DashMap<(Slot, Hash), Instant>,
        response_packet_batches: &[PacketBatch],
        _blockstore: &Blockstore,
        _outstanding_requests: &RwLock<OutstandingBlockIdRepairs>,
        stats: &mut BlockIdRepairResponsesStats,
        _retryable_requests_sender: &RetryableRequestsSender,
        _keypair: &Keypair,
        _migration_status: &MigrationStatus,
    ) {
        for batch in response_packet_batches {
            stats.total_packets += batch.len();

            for packet in batch.iter() {
                let Some(response) = Self::deserialize_response(packet) else {
                    stats.invalid_packets += 1;
                    continue;
                };

                match response {
                    BlockIdRepairResponse::ParentFecSetCount { .. } => {
                        stats.parent_fec_set_count_responses += 1;
                    }
                    BlockIdRepairResponse::FecSetRoot { .. } => {
                        stats.fec_set_root_responses += 1;
                    }
                }

                stats.processed += 1;
                // Further processing would go here
            }
        }
    }

    fn deserialize_response(_packet: PacketRef) -> Option<BlockIdRepairResponse> {
        // Deserialize the packet into a BlockIdRepairResponse
        // This is a placeholder - actual implementation would handle the packet format
        None
    }

    pub fn join(self) -> thread::Result<()> {
        for thread_hdl in self.thread_hdls {
            thread_hdl.join()?;
        }
        Ok(())
    }
}
