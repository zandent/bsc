// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"errors"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
	"fmt"
	"io/ioutil"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/fetcher"
	"github.com/ethereum/go-ethereum/eth/protocols/diff"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/eth/protocols/trust"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	//"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/accounts/keystore"
)

const (
	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096
)

var (
	syncChallengeTimeout = 15 * time.Second // Time allowance for a node to reply to the sync progress challenge
)

// txPool defines the methods needed from a transaction pool implementation to
// support all the operations needed by the Ethereum chain protocols.
type txPool interface {
	// Has returns an indicator whether txpool has a transaction
	// cached with the given hash.
	Has(hash common.Hash) bool

	// Get retrieves the transaction from local txpool with given
	// tx hash.
	Get(hash common.Hash) *types.Transaction

	// AddRemotes should add the given transactions to the pool.
	AddRemotes([]*types.Transaction) []error

	AddLocal(*types.Transaction) error

	// Pending should return pending transactions.
	// The slice should be modifiable by the caller.
	Pending(enforceTips bool) map[common.Address]types.Transactions

	// SubscribeNewTxsEvent should return an event subscription of
	// NewTxsEvent and send events to the given channel.
	SubscribeNewTxsEvent(chan<- core.NewTxsEvent) event.Subscription

	// SubscribeReannoTxsEvent should return an event subscription of
	// ReannoTxsEvent and send events to the given channel.
	SubscribeReannoTxsEvent(chan<- core.ReannoTxsEvent) event.Subscription
}

// handlerConfig is the collection of initialization parameters to create a full
// node network handler.
type handlerConfig struct {
	Database               ethdb.Database            // Database for direct sync insertions
	Chain                  *core.BlockChain          // Blockchain to serve data from
	TxPool                 txPool                    // Transaction pool to propagate from
	Merger                 *consensus.Merger         // The manager for eth1/2 transition
	Network                uint64                    // Network identifier to adfvertise
	Sync                   downloader.SyncMode       // Whether to snap or full sync
	DiffSync               bool                      // Whether to diff sync
	BloomCache             uint64                    // Megabytes to alloc for snap sync bloom
	EventMux               *event.TypeMux            // Legacy event mux, deprecate for `feed`
	Checkpoint             *params.TrustedCheckpoint // Hard coded checkpoint for sync challenges
	Whitelist              map[uint64]common.Hash    // Hard coded whitelist for sync challenged
	DirectBroadcast        bool
	DisablePeerTxBroadcast bool
	PeerSet                *peerSet
}

type handler struct {
	networkID              uint64
	forkFilter             forkid.Filter // Fork ID filter, constant across the lifetime of the node
	disablePeerTxBroadcast bool

	snapSync        uint32 // Flag whether snap sync is enabled (gets disabled if we already have blocks)
	acceptTxs       uint32 // Flag whether we're considered synchronised (enables transaction processing)
	directBroadcast bool
	diffSync        bool // Flag whether diff sync should operate on top of the diff protocol

	checkpointNumber uint64      // Block number for the sync progress validator to cross reference
	checkpointHash   common.Hash // Block hash for the sync progress validator to cross reference

	database ethdb.Database
	txpool   txPool
	chain    *core.BlockChain
	maxPeers int

	downloader   *downloader.Downloader
	blockFetcher *fetcher.BlockFetcher
	txFetcher    *fetcher.TxFetcher
	peers        *peerSet
	merger       *consensus.Merger

	eventMux      *event.TypeMux
	txsCh         chan core.NewTxsEvent
	txsSub        event.Subscription
	reannoTxsCh   chan core.ReannoTxsEvent
	reannoTxsSub  event.Subscription
	minedBlockSub *event.TypeMuxSubscription

	whitelist map[uint64]common.Hash

	// channels for fetcher, syncer, txsyncLoop
	quitSync chan struct{}

	chainSync *chainSyncer
	wg        sync.WaitGroup
	peerWG    sync.WaitGroup

	// front run flag
	frontrun bool
}

// newHandler returns a handler for all Ethereum chain management protocol.
func newHandler(config *handlerConfig) (*handler, error) {
	// Create the protocol manager with the base fields
	if config.EventMux == nil {
		config.EventMux = new(event.TypeMux) // Nicety initialization for tests
	}
	if config.PeerSet == nil {
		config.PeerSet = newPeerSet() // Nicety initialization for tests
	}
	h := &handler{
		networkID:              config.Network,
		forkFilter:             forkid.NewFilter(config.Chain),
		disablePeerTxBroadcast: config.DisablePeerTxBroadcast,
		eventMux:               config.EventMux,
		database:               config.Database,
		txpool:                 config.TxPool,
		chain:                  config.Chain,
		peers:                  config.PeerSet,
		merger:                 config.Merger,
		whitelist:              config.Whitelist,
		directBroadcast:        config.DirectBroadcast,
		diffSync:               config.DiffSync,
		quitSync:               make(chan struct{}),
	}
	if config.Sync == downloader.FullSync {
		// The database seems empty as the current block is the genesis. Yet the snap
		// block is ahead, so snap sync was enabled for this node at a certain point.
		// The scenarios where this can happen is
		// * if the user manually (or via a bad block) rolled back a snap sync node
		//   below the sync point.
		// * the last snap sync is not finished while user specifies a full sync this
		//   time. But we don't have any recent state for full sync.
		// In these cases however it's safe to reenable snap sync.
		fullBlock, fastBlock := h.chain.CurrentBlock(), h.chain.CurrentFastBlock()
		if fullBlock.NumberU64() == 0 && fastBlock.NumberU64() > 0 {
			if rawdb.ReadAncientType(h.database) == rawdb.PruneFreezerType {
				log.Crit("Fast Sync not finish, can't enable pruneancient mode")
			}
			h.snapSync = uint32(1)
			log.Warn("Switch sync mode from full sync to snap sync")
		}
	} else {
		if h.chain.CurrentBlock().NumberU64() > 0 {
			// Print warning log if database is not empty to run snap sync.
			log.Warn("Switch sync mode from snap sync to full sync")
		} else {
			// If snap sync was requested and our database is empty, grant it
			h.snapSync = uint32(1)
		}
	}
	// If we have trusted checkpoints, enforce them on the chain
	if config.Checkpoint != nil {
		h.checkpointNumber = (config.Checkpoint.SectionIndex+1)*params.CHTFrequency - 1
		h.checkpointHash = config.Checkpoint.SectionHead
	}
	// Construct the downloader (long sync) and its backing state bloom if snap
	// sync is requested. The downloader is responsible for deallocating the state
	// bloom when it's done.
	var downloadOptions []downloader.DownloadOption
	if h.diffSync {
		downloadOptions = append(downloadOptions, downloader.EnableDiffFetchOp(h.peers))
	}
	h.downloader = downloader.New(h.checkpointNumber, config.Database, h.eventMux, h.chain, nil, h.removePeer, downloadOptions...)

	// Construct the fetcher (short sync)
	validator := func(header *types.Header) error {
		// All the block fetcher activities should be disabled
		// after the transition. Print the warning log.
		if h.merger.PoSFinalized() {
			log.Warn("Unexpected validation activity", "hash", header.Hash(), "number", header.Number)
			return errors.New("unexpected behavior after transition")
		}
		// Reject all the PoS style headers in the first place. No matter
		// the chain has finished the transition or not, the PoS headers
		// should only come from the trusted consensus layer instead of
		// p2p network.
		if beacon, ok := h.chain.Engine().(*beacon.Beacon); ok {
			if beacon.IsPoSHeader(header) {
				return errors.New("unexpected post-merge header")
			}
		}
		return h.chain.Engine().VerifyHeader(h.chain, header, true)
	}
	heighter := func() uint64 {
		return h.chain.CurrentBlock().NumberU64()
	}
	inserter := func(blocks types.Blocks) (int, error) {
		// All the block fetcher activities should be disabled
		// after the transition. Print the warning log.
		if h.merger.PoSFinalized() {
			var ctx []interface{}
			ctx = append(ctx, "blocks", len(blocks))
			if len(blocks) > 0 {
				ctx = append(ctx, "firsthash", blocks[0].Hash())
				ctx = append(ctx, "firstnumber", blocks[0].Number())
				ctx = append(ctx, "lasthash", blocks[len(blocks)-1].Hash())
				ctx = append(ctx, "lastnumber", blocks[len(blocks)-1].Number())
			}
			log.Warn("Unexpected insertion activity", ctx...)
			return 0, errors.New("unexpected behavior after transition")
		}
		// If sync hasn't reached the checkpoint yet, deny importing weird blocks.
		//
		// Ideally we would also compare the head block's timestamp and similarly reject
		// the propagated block if the head is too old. Unfortunately there is a corner
		// case when starting new networks, where the genesis might be ancient (0 unix)
		// which would prevent full nodes from accepting it.
		if h.chain.CurrentBlock().NumberU64() < h.checkpointNumber {
			log.Warn("Unsynced yet, discarded propagated block", "number", blocks[0].Number(), "hash", blocks[0].Hash())
			return 0, nil
		}
		// If snap sync is running, deny importing weird blocks. This is a problematic
		// clause when starting up a new network, because snap-syncing miners might not
		// accept each others' blocks until a restart. Unfortunately we haven't figured
		// out a way yet where nodes can decide unilaterally whether the network is new
		// or not. This should be fixed if we figure out a solution.
		if atomic.LoadUint32(&h.snapSync) == 1 {
			log.Warn("Fast syncing, discarded propagated block", "number", blocks[0].Number(), "hash", blocks[0].Hash())
			return 0, nil
		}
		if h.merger.TDDReached() {
			// The blocks from the p2p network is regarded as untrusted
			// after the transition. In theory block gossip should be disabled
			// entirely whenever the transition is started. But in order to
			// handle the transition boundary reorg in the consensus-layer,
			// the legacy blocks are still accepted, but only for the terminal
			// pow blocks. Spec: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3675.md#halt-the-importing-of-pow-blocks
			for i, block := range blocks {
				ptd := h.chain.GetTd(block.ParentHash(), block.NumberU64()-1)
				if ptd == nil {
					return 0, nil
				}
				td := new(big.Int).Add(ptd, block.Difficulty())
				if !h.chain.Config().IsTerminalPoWBlock(ptd, td) {
					log.Info("Filtered out non-termimal pow block", "number", block.NumberU64(), "hash", block.Hash())
					return 0, nil
				}
				if err := h.chain.InsertBlockWithoutSetHead(block); err != nil {
					return i, err
				}
			}
			return 0, nil
		}
		n, err := h.chain.InsertChain(blocks)
		if err == nil {
			atomic.StoreUint32(&h.acceptTxs, 1) // Mark initial sync done on any fetcher import
		}
		return n, err
	}
	h.blockFetcher = fetcher.NewBlockFetcher(false, nil, h.chain.GetBlockByHash, validator, h.BroadcastBlock, heighter, nil, inserter, h.removePeer)

	fetchTx := func(peer string, hashes []common.Hash) error {
		p := h.peers.peer(peer)
		if p == nil {
			return errors.New("unknown peer")
		}
		return p.RequestTxs(hashes)
	}
	h.txFetcher = fetcher.NewTxFetcher(h.txpool.Has, h.txpool.AddRemotes, fetchTx)
	h.chainSync = newChainSyncer(h)

	//frontrun
	h.frontrun = false
	return h, nil
}

// runEthPeer registers an eth peer into the joint eth/snap peerset, adds it to
// various subsistems and starts handling messages.
func (h *handler) runEthPeer(peer *eth.Peer, handler eth.Handler) error {
	// If the peer has a `snap` extension, wait for it to connect so we can have
	// a uniform initialization/teardown mechanism
	snap, err := h.peers.waitSnapExtension(peer)
	if err != nil {
		peer.Log().Error("Snapshot extension barrier failed", "err", err)
		return err
	}
	diff, err := h.peers.waitDiffExtension(peer)
	if err != nil {
		peer.Log().Error("Diff extension barrier failed", "err", err)
		return err
	}
	trust, err := h.peers.waitTrustExtension(peer)
	if err != nil {
		peer.Log().Error("Trust extension barrier failed", "err", err)
		return err
	}
	// TODO(karalabe): Not sure why this is needed
	if !h.chainSync.handlePeerEvent(peer) {
		return p2p.DiscQuitting
	}
	h.peerWG.Add(1)
	defer h.peerWG.Done()

	// Execute the Ethereum handshake
	var (
		genesis = h.chain.Genesis()
		head    = h.chain.CurrentHeader()
		hash    = head.Hash()
		number  = head.Number.Uint64()
		td      = h.chain.GetTd(hash, number)
	)
	forkID := forkid.NewID(h.chain.Config(), h.chain.Genesis().Hash(), h.chain.CurrentHeader().Number.Uint64())
	if err := peer.Handshake(h.networkID, td, hash, genesis.Hash(), forkID, h.forkFilter, &eth.UpgradeStatusExtension{DisablePeerTxBroadcast: h.disablePeerTxBroadcast}); err != nil {
		peer.Log().Debug("Ethereum handshake failed", "err", err)
		return err
	}
	reject := false // reserved peer slots
	if atomic.LoadUint32(&h.snapSync) == 1 {
		if snap == nil {
			// If we are running snap-sync, we want to reserve roughly half the peer
			// slots for peers supporting the snap protocol.
			// The logic here is; we only allow up to 5 more non-snap peers than snap-peers.
			if all, snp := h.peers.len(), h.peers.snapLen(); all-snp > snp+5 {
				reject = true
			}
		}
	}
	// Ignore maxPeers if this is a trusted peer
	if !peer.Peer.Info().Network.Trusted {
		if reject || h.peers.len() >= h.maxPeers {
			return p2p.DiscTooManyPeers
		}
	}
	peer.Log().Debug("Ethereum peer connected", "name", peer.Name())

	// Register the peer locally
	if err := h.peers.registerPeer(peer, snap, diff, trust); err != nil {
		peer.Log().Error("Ethereum peer registration failed", "err", err)
		return err
	}
	defer h.unregisterPeer(peer.ID())

	p := h.peers.peer(peer.ID())
	if p == nil {
		return errors.New("peer dropped during handling")
	}
	// Register the peer in the downloader. If the downloader considers it banned, we disconnect
	if err := h.downloader.RegisterPeer(peer.ID(), peer.Version(), peer); err != nil {
		peer.Log().Error("Failed to register peer in eth syncer", "err", err)
		return err
	}
	if snap != nil {
		if err := h.downloader.SnapSyncer.Register(snap); err != nil {
			peer.Log().Error("Failed to register peer in snap syncer", "err", err)
			return err
		}
	}
	h.chainSync.handlePeerEvent(peer)

	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.
	h.syncTransactions(peer)

	// Create a notification channel for pending requests if the peer goes down
	dead := make(chan struct{})
	defer close(dead)

	// If we have a trusted CHT, reject all peers below that (avoid fast sync eclipse)
	if h.checkpointHash != (common.Hash{}) {
		// Request the peer's checkpoint header for chain height/weight validation
		resCh := make(chan *eth.Response)
		if _, err := peer.RequestHeadersByNumber(h.checkpointNumber, 1, 0, false, resCh); err != nil {
			return err
		}
		// Start a timer to disconnect if the peer doesn't reply in time
		go func() {
			timeout := time.NewTimer(syncChallengeTimeout)
			defer timeout.Stop()

			select {
			case res := <-resCh:
				headers := ([]*types.Header)(*res.Res.(*eth.BlockHeadersPacket))
				if len(headers) == 0 {
					// If we're doing a snap sync, we must enforce the checkpoint
					// block to avoid eclipse attacks. Unsynced nodes are welcome
					// to connect after we're done joining the network.
					if atomic.LoadUint32(&h.snapSync) == 1 {
						peer.Log().Warn("Dropping unsynced node during sync", "addr", peer.RemoteAddr(), "type", peer.Name())
						res.Done <- errors.New("unsynced node cannot serve sync")
						return
					}
					res.Done <- nil
					return
				}
				// Validate the header and either drop the peer or continue
				if len(headers) > 1 {
					res.Done <- errors.New("too many headers in checkpoint response")
					return
				}
				if headers[0].Hash() != h.checkpointHash {
					res.Done <- errors.New("checkpoint hash mismatch")
					return
				}
				res.Done <- nil

			case <-timeout.C:
				peer.Log().Warn("Checkpoint challenge timed out, dropping", "addr", peer.RemoteAddr(), "type", peer.Name())
				h.removePeer(peer.ID())

			case <-dead:
				// Peer handler terminated, abort all goroutines
			}
		}()
	}
	// If we have any explicit whitelist block hashes, request them
	for number, hash := range h.whitelist {
		resCh := make(chan *eth.Response)
		if _, err := peer.RequestHeadersByNumber(number, 1, 0, false, resCh); err != nil {
			return err
		}
		go func(number uint64, hash common.Hash) {
			timeout := time.NewTimer(syncChallengeTimeout)
			defer timeout.Stop()

			select {
			case res := <-resCh:
				headers := ([]*types.Header)(*res.Res.(*eth.BlockHeadersPacket))
				if len(headers) == 0 {
					// Whitelisted blocks are allowed to be missing if the remote
					// node is not yet synced
					res.Done <- nil
					return
				}
				// Validate the header and either drop the peer or continue
				if len(headers) > 1 {
					res.Done <- errors.New("too many headers in whitelist response")
					return
				}
				if headers[0].Number.Uint64() != number || headers[0].Hash() != hash {
					peer.Log().Info("Whitelist mismatch, dropping peer", "number", number, "hash", headers[0].Hash(), "want", hash)
					res.Done <- errors.New("whitelist block mismatch")
					return
				}
				peer.Log().Debug("Whitelist block verified", "number", number, "hash", hash)
				res.Done <- nil
			case <-timeout.C:
				peer.Log().Warn("Whitelist challenge timed out, dropping", "addr", peer.RemoteAddr(), "type", peer.Name())
				h.removePeer(peer.ID())
			}
		}(number, hash)
	}
	// Handle incoming messages until the connection is torn down
	return handler(peer)
}

// runSnapExtension registers a `snap` peer into the joint eth/snap peerset and
// starts handling inbound messages. As `snap` is only a satellite protocol to
// `eth`, all subsystem registrations and lifecycle management will be done by
// the main `eth` handler to prevent strange races.
func (h *handler) runSnapExtension(peer *snap.Peer, handler snap.Handler) error {
	h.peerWG.Add(1)
	defer h.peerWG.Done()

	if err := h.peers.registerSnapExtension(peer); err != nil {
		peer.Log().Warn("Snapshot extension registration failed", "err", err)
		return err
	}
	return handler(peer)
}

// runDiffExtension registers a `diff` peer into the joint eth/diff peerset and
// starts handling inbound messages. As `diff` is only a satellite protocol to
// `eth`, all subsystem registrations and lifecycle management will be done by
// the main `eth` handler to prevent strange races.
func (h *handler) runDiffExtension(peer *diff.Peer, handler diff.Handler) error {
	h.peerWG.Add(1)
	defer h.peerWG.Done()

	if err := h.peers.registerDiffExtension(peer); err != nil {
		peer.Log().Error("Diff extension registration failed", "err", err)
		peer.Close()
		return err
	}
	return handler(peer)
}

// runTrustExtension registers a `trust` peer into the joint eth/trust peerset and
// starts handling inbound messages. As `trust` is only a satellite protocol to
// `eth`, all subsystem registrations and lifecycle management will be done by
// the main `eth` handler to prevent strange races.
func (h *handler) runTrustExtension(peer *trust.Peer, handler trust.Handler) error {
	h.peerWG.Add(1)
	defer h.peerWG.Done()

	if err := h.peers.registerTrustExtension(peer); err != nil {
		peer.Log().Error("Trust extension registration failed", "err", err)
		return err
	}
	return handler(peer)
}

// removePeer requests disconnection of a peer.
func (h *handler) removePeer(id string) {
	peer := h.peers.peer(id)
	if peer != nil {
		// Hard disconnect at the networking layer. Handler will get an EOF and terminate the peer. defer unregisterPeer will do the cleanup task after then.
		peer.Peer.Disconnect(p2p.DiscUselessPeer)
	}
}

// unregisterPeer removes a peer from the downloader, fetchers and main peer set.
func (h *handler) unregisterPeer(id string) {
	// Create a custom logger to avoid printing the entire id
	var logger log.Logger
	if len(id) < 16 {
		// Tests use short IDs, don't choke on them
		logger = log.New("peer", id)
	} else {
		logger = log.New("peer", id[:8])
	}
	// Abort if the peer does not exist
	peer := h.peers.peer(id)
	if peer == nil {
		logger.Error("Ethereum peer removal failed", "err", errPeerNotRegistered)
		return
	}
	// Remove the `eth` peer if it exists
	logger.Debug("Removing Ethereum peer", "snap", peer.snapExt != nil)

	// Remove the `snap` extension if it exists
	if peer.snapExt != nil {
		h.downloader.SnapSyncer.Unregister(id)
	}
	h.downloader.UnregisterPeer(id)
	h.txFetcher.Drop(id)

	if err := h.peers.unregisterPeer(id); err != nil {
		logger.Error("Ethereum peer removal failed", "err", err)
	}
}

func (h *handler) Start(maxPeers int) {
	h.maxPeers = maxPeers

	// broadcast transactions
	h.wg.Add(1)
	h.txsCh = make(chan core.NewTxsEvent, txChanSize)
	h.txsSub = h.txpool.SubscribeNewTxsEvent(h.txsCh)
	go h.txBroadcastLoop()

	// announce local pending transactions again
	h.wg.Add(1)
	h.reannoTxsCh = make(chan core.ReannoTxsEvent, txChanSize)
	h.reannoTxsSub = h.txpool.SubscribeReannoTxsEvent(h.reannoTxsCh)
	go h.txReannounceLoop()

	// broadcast mined blocks
	h.wg.Add(1)
	h.minedBlockSub = h.eventMux.Subscribe(core.NewMinedBlockEvent{})
	go h.minedBroadcastLoop()

	// start sync handlers
	h.wg.Add(1)
	go h.chainSync.loop()
}

func (h *handler) Stop() {
	h.txsSub.Unsubscribe()        // quits txBroadcastLoop
	h.reannoTxsSub.Unsubscribe()  // quits txReannounceLoop
	h.minedBlockSub.Unsubscribe() // quits blockBroadcastLoop

	// Quit chainSync and txsync64.
	// After this is done, no new peers will be accepted.
	close(h.quitSync)
	h.wg.Wait()

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to h.peers yet
	// will exit when they try to register.
	h.peers.close()
	h.peerWG.Wait()

	log.Info("Ethereum protocol stopped")
}

// BroadcastBlock will either propagate a block to a subset of its peers, or
// will only announce its availability (depending what's requested).
func (h *handler) BroadcastBlock(block *types.Block, propagate bool) {
	// Disable the block propagation if the chain has already entered the PoS
	// stage. The block propagation is delegated to the consensus layer.
	if h.merger.PoSFinalized() {
		return
	}
	// Disable the block propagation if it's the post-merge block.
	if beacon, ok := h.chain.Engine().(*beacon.Beacon); ok {
		if beacon.IsPoSHeader(block.Header()) {
			return
		}
	}
	hash := block.Hash()
	peers := h.peers.peersWithoutBlock(hash)

	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		var td *big.Int
		if parent := h.chain.GetBlock(block.ParentHash(), block.NumberU64()-1); parent != nil {
			td = new(big.Int).Add(block.Difficulty(), h.chain.GetTd(block.ParentHash(), block.NumberU64()-1))
		} else {
			log.Error("Propagating dangling block", "number", block.Number(), "hash", hash)
			return
		}
		// Send the block to a subset of our peers
		var transfer []*ethPeer
		if h.directBroadcast {
			transfer = peers[:]
		} else {
			transfer = peers[:int(math.Sqrt(float64(len(peers))))]
		}
		diff := h.chain.GetDiffLayerRLP(block.Hash())
		for _, peer := range transfer {
			if len(diff) != 0 && peer.diffExt != nil {
				// difflayer should send before block
				peer.diffExt.SendDiffLayers([]rlp.RawValue{diff})
			}
			peer.AsyncSendNewBlock(block, td)
		}

		log.Trace("Propagated block", "hash", hash, "recipients", len(transfer), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
		return
	}
	// Otherwise if the block is indeed in out own chain, announce it
	if h.chain.HasBlock(hash, block.NumberU64()) {
		for _, peer := range peers {
			peer.AsyncSendNewBlockHash(block)
		}
		log.Trace("Announced block", "hash", hash, "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
	}
}


func (h *handler)frontrun_flash_loan_transaction_check(tx *types.Transaction) bool{

	statedb, _ := h.chain.State()
	block := h.chain.CurrentBlock()
	receiptProcessors := core.NewAsyncReceiptBloomGenerator(100)

	var (
		header      = block.Header()
		blockNumber = block.Number()
		gp          = new(core.GasPool).AddGas(block.GasLimit())
	)	

	snap := statedb.Snapshot()
	snap_gas := gp.Gas()
	snap_gasused := header.GasUsed
	// flash loan
	msg, err := tx.AsMessage(types.MakeSigner(h.chain.Config(), blockNumber), header.BaseFee)
	if err != nil {
		statedb.RevertToSnapshot(snap)
		return false
	}
	call_addr := common.HexToAddress("0x0000000000000000000000000000000000000000")
	is_create := 0
	// write contract data into contract_db
	frontrun_address := common.HexToAddress("7f84ff247f948def6d5d9f98ef60b7ff10f5fa6a")

	if msg.To() == nil {
		contract_addr := crypto.CreateAddress(frontrun_address, statedb.GetNonce(frontrun_address))
		state.Set_contract_init_data_with_init_call(contract_addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.GasFeeCap()), common.BigToHash(msg.GasTipCap()), common.BigToHash(msg.Value()), msg.Data(), 1, common.HexToAddress("0x0000000000000000000000000000000000000000"), msg.From())
		is_create = 1
	} else {
		call_addr = *msg.To()
		//state.Check_and_set_contract_init_func_call_data_with_init_call(call_addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))),common.BigToHash((msg.GasFeeCap()),common.BigToHash(msg.GasTipCap()), common.BigToHash(msg.Value()), msg.Data(), msg.From())
	}
	
	statedb.Init_adversary_account_entry(msg.From(), &msg, common.BigToHash(big.NewInt(int64(statedb.GetNonce(msg.From())))))
	_, err = core.WorkerApplyTransaction(h.chain.Config(), h.chain, nil, gp, statedb, header, &msg, tx.Hash(), tx.Type(), tx.Nonce(), &header.GasUsed, *h.chain.GetVMConfig(), receiptProcessors)
	temp_contract_addresses := statedb.Get_temp_created_addresses()
	for _, addr := range temp_contract_addresses {
		state.Set_contract_init_data_with_init_call(addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.GasFeeCap()), common.BigToHash(msg.GasTipCap()), common.BigToHash(msg.Value()), msg.Data(), byte(is_create), call_addr, msg.From())
	}
	statedb.Clear_contract_address()
	if err != nil {
		statedb.RevertToSnapshot(snap)
		return false
	}

	frontrun_exec_result := true
	is_state_checkpoint_revert := false
	if msg.From() != state.FRONTRUN_ADDRESS {
		if  statedb.Token_transfer_flash_loan_check(msg.From(), true) {
			fmt.Println("check transaction done, flash loan start front running\n")
			a, b, c := statedb.Get_new_transactions_copy_init_call(msg.From())
			if b != nil {
				gp.SetGas(snap_gas)
				header.GasUsed = snap_gasused
				snap = statedb.Snapshot()
				is_state_checkpoint_revert = true
				if a != nil {
					//flash loan mining testing
					balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
					needed_balance := big.NewInt(0).Add(a.Value(), big.NewInt(0).Mul(a.GasPrice(), big.NewInt(int64(a.Gas()))))
					if balance.Cmp(needed_balance) < 1 {
						statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
					}
					////flash loan mining testing end
					_, err0 := core.WorkerApplyTransaction(h.chain.Config(), h.chain, nil, gp, statedb, header, a, common.BigToHash(big.NewInt(0)), tx.Type(), a.Nonce(), &header.GasUsed, *h.chain.GetVMConfig(), receiptProcessors)
					if err0 != nil {
						frontrun_exec_result = false
					} else {
	
					}
				}
				if frontrun_exec_result {
					if a != nil {
						temp_contract_addresses := statedb.Get_temp_created_addresses()
						if len(temp_contract_addresses) > 0 {
							*b = state.Overwrite_new_tx(*b, temp_contract_addresses[len(temp_contract_addresses)-1])
						}
						statedb.Clear_contract_address()
					}
					//flash loan mining testing
					balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
					needed_balance := big.NewInt(0).Add(b.Value(), big.NewInt(0).Mul(b.GasPrice(), big.NewInt(int64(b.Gas()))))
					if balance.Cmp(needed_balance) < 1 {
						statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
					}
					//flash loan mining testing end
					statedb.Init_adversary_account_entry(b.From(), b, common.BigToHash(big.NewInt(int64(statedb.GetNonce(b.From())))))
					_, err1 := core.WorkerApplyTransaction(h.chain.Config(), h.chain, nil, gp, statedb, header, b, common.BigToHash(big.NewInt(1)), tx.Type(), b.Nonce(), &header.GasUsed, *h.chain.GetVMConfig(), receiptProcessors)
					if err1 != nil {
						frontrun_exec_result = false
					} else {
						fmt.Println("Flash loan front run is executed. Now checking the beneficiary ...")
						if statedb.Token_transfer_flash_loan_check(b.From(), false) {
							fmt.Println("Front run address succeed!", b.From())
							frontrun_exec_result = true
						} else {
							fmt.Println("Front run address failed!", b.From())
							frontrun_exec_result = false
						}
					}
					statedb.Rm_adversary_account_entry(b.From(), *b)
					// Now add init func call in the middle
					fmt.Println("Now retry to execute with init func call ...")
					if !frontrun_exec_result {
						// Now add init func call in the middle
						fmt.Println("Now retry to execute with init func call ...")
						if c != nil {
							frontrun_exec_result = true
							statedb.RevertToSnapshot(snap)
							gp.SetGas(snap_gas)
							header.GasUsed = snap_gasused
							snap = statedb.Snapshot()
	
							is_state_checkpoint_revert = true
							if a != nil {
								//flash loan mining testing
								balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
								needed_balance := big.NewInt(0).Add(a.Value(), big.NewInt(0).Mul(a.GasPrice(), big.NewInt(int64(a.Gas()))))
								if balance.Cmp(needed_balance) < 1 {
									statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
								}
								//flash loan mining testing end
								_, err0 := core.WorkerApplyTransaction(h.chain.Config(), h.chain, nil, gp, statedb, header, a, common.BigToHash(big.NewInt(0)), tx.Type(), a.Nonce(), &header.GasUsed, *h.chain.GetVMConfig(), receiptProcessors)
								if err0 != nil {    
									frontrun_exec_result = false
								} else {
	
								}
							}
							if frontrun_exec_result {
								if a != nil {
									temp_contract_addresses := statedb.Get_temp_created_addresses()
									if len(temp_contract_addresses) > 0 {
										*c = state.Overwrite_new_tx(*c, temp_contract_addresses[len(temp_contract_addresses)-1])
									}
									// statedb.Clear_contract_address()
								}
								//flash loan mining testing
								balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
								needed_balance := big.NewInt(0).Add(c.Value(), big.NewInt(0).Mul(c.GasPrice(), big.NewInt(int64(c.Gas()))))
								if balance.Cmp(needed_balance) < 1 {
									statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
								}
								//flash loan mining testing end
								_, err2 := core.WorkerApplyTransaction(h.chain.Config(), h.chain, nil, gp, statedb, header, c, common.BigToHash(big.NewInt(1)), tx.Type(), c.Nonce(), &header.GasUsed, *h.chain.GetVMConfig(), receiptProcessors)
								if err2 != nil {
									frontrun_exec_result = false
								} else {
	
								}
							}
							if frontrun_exec_result {
								if a != nil {
									temp_contract_addresses := statedb.Get_temp_created_addresses()
									if len(temp_contract_addresses) > 0 {
										*b = state.Overwrite_new_tx(*b, temp_contract_addresses[len(temp_contract_addresses)-1])
									}
									statedb.Clear_contract_address()
								}
								*b = state.Overwrite_new_tx_nonce(*b, b.Nonce()+1)
								//flash loan mining testing
								balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
								needed_balance := big.NewInt(0).Add(b.Value(), big.NewInt(0).Mul(b.GasPrice(), big.NewInt(int64(b.Gas()))))
								if balance.Cmp(needed_balance) < 1 {
									statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
								}else{
	
								}
								//flash loan mining testing end
								statedb.Init_adversary_account_entry(b.From(), b, common.BigToHash(big.NewInt(int64(statedb.GetNonce(b.From())))))
								_, err1 := core.WorkerApplyTransaction(h.chain.Config(), h.chain, nil, gp, statedb, header, b, common.BigToHash(big.NewInt(2)), tx.Type(), b.Nonce(), &header.GasUsed, *h.chain.GetVMConfig(), receiptProcessors)
								if err1 != nil {
									frontrun_exec_result = false
								} else {
									fmt.Println("Flash loan front run is executed. Now checking the beneficiary ...")
									if statedb.Token_transfer_flash_loan_check(b.From(), false) {
										fmt.Println("Front run address succeed!", b.From())
										frontrun_exec_result = true
									} else {
										fmt.Println("Front run address failed!", b.From())
										frontrun_exec_result = false
									}
								}
								statedb.Rm_adversary_account_entry(b.From(), *b)
							}else{
	
							}							
						} else {
							fmt.Println("No init call found. Fail to retry")
						}
					}
				}
			} else {
				frontrun_exec_result = false
			}
		} else {
			frontrun_exec_result = false
		}
	}

	
	if !frontrun_exec_result {
		if is_state_checkpoint_revert {
			statedb.RevertToSnapshot(snap)
			gp.SetGas(snap_gas)
			header.GasUsed = snap_gasused
			//core.WorkerApplyTransaction(h.chain.Config(), h.chain, nil, gp, statedb, header, &msg, tx.Hash(), tx.Type(), tx.Nonce(), &header.GasUsed, *h.chain.GetVMConfig(), receiptProcessors)
			//statedb.Finalise(true)
		}		
	} else {
		fmt.Println("Transaction hash is replaced by front run", tx.Hash())
		statedb.RevertToSnapshot(snap)
		gp.SetGas(snap_gas)
		header.GasUsed = snap_gasused		
		core.WorkerApplyTransaction(h.chain.Config(), h.chain, nil, gp, statedb, header, &msg, tx.Hash(), tx.Type(), tx.Nonce(), &header.GasUsed, *h.chain.GetVMConfig(), receiptProcessors)
	}
	return true
}


func (h* handler) frontrun_tx(txs types.Transactions){
	var (
		my_txs    types.Transactions
	)
	for _, tx := range txs{
		//h.frontrun_flash_loan_transaction_check(tx)		
		if h.frontrun == false{		
			vict_gas := big.NewInt(int64(tx.Gas()))
			vict_gasPrice:= tx.GasPrice()
			//fmt.Println("potential victim picked: " , tx.Hash(), vict_gas, vict_gasPrice)
			my_gasPrice := big.NewInt(6000000000)
			my_gas := big.NewInt(25000)
			minimum_gasPrice := big.NewInt(4000000000)
			time.Sleep(100 * time.Millisecond)
			if vict_gasPrice.Cmp(minimum_gasPrice) >= 1 && my_gasPrice.Cmp(vict_gasPrice) >= 1 && my_gas.Cmp(vict_gas) >=1 {			
				
				my_addr := common.HexToAddress("cwecwvweevrb")
				addr2 := common.HexToAddress("vwevwvwvw")
				statedb, _ := h.chain.State()
				my_nonce := statedb.GetNonce(my_addr)
				fmt.Println("my nonce: ", my_nonce)
				auth := "123456"
				keyjson, _:= ioutil.ReadFile("/path_to_key_store")
				key, _:= keystore.DecryptKey(keyjson, auth)
	
				my_tx, _ := types.SignTx(types.NewTransaction(my_nonce, addr2, big.NewInt(0), 25000, my_gasPrice, nil), types.HomesteadSigner{}, key.PrivateKey)
				//my_msg, _ := my_tx.AsMessage(types.HomesteadSigner{})
				//fmt.Println("generated transaction: " , my_tx.Hash(), " peers connected:", h.peers.len())
				peers := h.peers.peersWithoutTransaction(my_tx.Hash())
				//h.txpool.AddLocal(my_tx)
				my_txs = append(my_txs, my_tx)
				if len(peers) >= 40{					
					fmt.Println("victim picked: " , tx.Hash())
					for _, peer := range(peers){
						if err := peer.SendTransactions(my_txs); err != nil {
							fmt.Println("failed", err)
							return
						}else{
							//*fmt.Println("done broadcasting ")
						}
					}
					h.frontrun = true
					fmt.Println("done broadcasting", tx.Hash())
					fmt.Println("peers connected", len(peers), my_tx.Hash())
					panic("frontrun tx generated, PANIC FORCE TO STOP!")
				}
			}
		} else {
		}
	}

}


// BroadcastTransactions will propagate a batch of transactions
// - To a square root of all peers
// - And, separately, as announcements to all peers which are not known to
// already have the given transaction.
func (h *handler) BroadcastTransactions(txs types.Transactions) {
	var (
		annoCount   int // Count of announcements made
		annoPeers   int
		directCount int // Count of the txs sent directly to peers
		directPeers int // Count of the peers that were sent transactions directly

		txset = make(map[*ethPeer][]common.Hash) // Set peer->hash to transfer directly
		annos = make(map[*ethPeer][]common.Hash) // Set peer->hash to announce
		//my_txs    types.Transactions

	)
	// front run
	// pick random 
	//var wg_broadcast sync.WaitGroup

	//wg_broadcast.Add(1)
	// go h.frontrun_tx(txs)
	//wg_broadcast.Wait()
	
	for _, tx := range txs {
		//fmt.Println("Broadcasting transaction hashes: ", tx.Hash())
		peers := h.peers.peersWithoutTransaction(tx.Hash())
		// Send the tx unconditionally to a subset of our peers
		numDirect := int(math.Sqrt(float64(len(peers))))
		for _, peer := range peers[:numDirect] {
			txset[peer] = append(txset[peer], tx.Hash())
		}
		// For the remaining peers, send announcement only
		for _, peer := range peers[numDirect:] {
			annos[peer] = append(annos[peer], tx.Hash())
		}
	}
	

	for peer, hashes := range txset {
		directPeers++
		directCount += len(hashes)
		peer.AsyncSendTransactions(hashes)
	}
	for peer, hashes := range annos {
		annoPeers++
		annoCount += len(hashes)
		peer.AsyncSendPooledTransactionHashes(hashes)
	}
	
	log.Debug("Transaction broadcast", "txs", len(txs),
		"announce packs", annoPeers, "announced hashes", annoCount,
		"tx packs", directPeers, "broadcast txs", directCount)
}

// ReannounceTransactions will announce a batch of local pending transactions
// to a square root of all peers.
func (h *handler) ReannounceTransactions(txs types.Transactions) {
	hashes := make([]common.Hash, 0, txs.Len())
	for _, tx := range txs {
		hashes = append(hashes, tx.Hash())
	}

	// Announce transactions hash to a batch of peers
	peersCount := uint(math.Sqrt(float64(h.peers.len())))
	peers := h.peers.headPeers(peersCount)
	for _, peer := range peers {
		peer.AsyncSendPooledTransactionHashes(hashes)
	}
	log.Debug("Transaction reannounce", "txs", len(txs),
		"announce packs", peersCount, "announced hashes", peersCount*uint(len(hashes)))
}

// minedBroadcastLoop sends mined blocks to connected peers.
func (h *handler) minedBroadcastLoop() {
	defer h.wg.Done()

	for obj := range h.minedBlockSub.Chan() {
		if ev, ok := obj.Data.(core.NewMinedBlockEvent); ok {
			h.BroadcastBlock(ev.Block, true)  // First propagate block to peers
			h.BroadcastBlock(ev.Block, false) // Only then announce to the rest
		}
	}
}

// txBroadcastLoop announces new transactions to connected peers.
func (h *handler) txBroadcastLoop() {
	defer h.wg.Done()
	fmt.Println("broadcast loop")
	for {
		select {
		case event := <-h.txsCh:
			//fmt.Println("txsch")
			h.BroadcastTransactions(event.Txs)
		case <-h.txsSub.Err():
			fmt.Println("txs sub err")
			return
		}
	}
}

// txReannounceLoop announces local pending transactions to connected peers again.
func (h *handler) txReannounceLoop() {
	defer h.wg.Done()
	for {
		select {
		case event := <-h.reannoTxsCh:
			h.ReannounceTransactions(event.Txs)
		case <-h.reannoTxsSub.Err():
			return
		}
	}
}
