// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ProtegoGuard
 * @dev Flattened single-file contract intended for hackathon Phase 1.
 *      Acts as an on-chain registry and forensic log for pending transactions
 *      detected by an off-chain detection engine (SecureDApp Shield).
 *
 *      The contract purpose for Phase 1:
 *      - Provide a minimal, auditable on-chain component that records:
 *          * user-submitted pending tx metadata
 *          * alerts raised by an authorized oracle/detection engine
 *          * protection actions (e.g., mark tx as privately submitted)
 *      - Be small, secure, and easy to inspect/flatten for AuditExpress.
 *
 * NOTES:
 * - This contract DOES NOT attempt to submit private transactions to Flashbots
 *   (that must be done off-chain). Instead it stores proofs/notes and emits
 *   events suitable for on-chain auditing and later forensic export.
 * - The design emphasizes clarity, explicit access control, and event-driven
 *   logging to make audits straightforward.
 */

/* --------------------------------------------------------------------------
 * Minimal OpenZeppelin-style Ownable + ReentrancyGuard + Pausable inlined
 * (kept small for audit friendliness). This is not the full OZ codebase but
 * includes the relevant safety checks used below.
 * -------------------------------------------------------------------------- */

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}

contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _owner = _msgSender();
        emit OwnershipTransferred(address(0), _owner);
    }

    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

contract ReentrancyGuard {
    uint256 private _status;
    constructor() { _status = 1; }
    modifier nonReentrant() {
        require(_status == 1, "ReentrancyGuard: reentrant call");
        _status = 2;
        _;
        _status = 1;
    }
}

contract Pausable is Ownable {
    bool private _paused;
    event Paused(address account);
    event Unpaused(address account);

    constructor() { _paused = false; }

    modifier whenNotPaused() {
        require(!_paused, "Pausable: paused");
        _;
    }

    modifier whenPaused() {
        require(_paused, "Pausable: not paused");
        _;
    }

    function paused() public view returns (bool) {
        return _paused;
    }

    function _pause() internal whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }

    function _unpause() internal whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }

    // Expose owner-only pause/unpause
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}

/* --------------------------------------------------------------------------
 * ProtegoGuard contract
 * -------------------------------------------------------------------------- */

contract ProtegoGuard is Pausable, ReentrancyGuard {
    /// @notice Address authorized to call detection/oracle-only methods
    address public oracle;

    /// @notice Incremental id for pending txs
    uint256 private _nextId;

    enum RiskLevel { None, Low, Medium, High }

    struct PendingTx {
        uint256 id;
        address submitter; // who registered the pending tx
        address target; // e.g., DEX router
        uint256 value; // ETH value attached
        bytes calldataData; // calldata bytes (small payload expected)
        uint256 gasPrice; // gas price at registration (wei)
        uint256 maxSlippageBps; // slippage tolerance in basis points (1 bps = 0.01%)
        uint256 timestamp;
        bool protectedFlag; // marked as privately submitted/protected
        string notes; // optional short note
    }

    struct Alert {
        uint256 pendingTxId;
        RiskLevel risk;
        uint256 confidence; // 0-100
        string reason;
        uint256 timestamp;
        address reporter; // oracle who reported
    }

    // Storage
    mapping(uint256 => PendingTx) private _pendingTxs;
    mapping(uint256 => Alert[]) private _alertsByTxId;

    // Events
    event PendingTxRegistered(uint256 indexed id, address indexed submitter, address target);
    event AlertRaised(uint256 indexed id, RiskLevel risk, uint256 confidence, string reason, address reporter);
    event TransactionProtected(uint256 indexed id, address protector, string proof);
    event OracleUpdated(address indexed previousOracle, address indexed newOracle);

    // Errors (custom errors save gas and help audits)
    error NotOracle();
    error InvalidId();
    error EmptyCalldata();

    modifier onlyOracle() {
        if (msg.sender != oracle) revert NotOracle();
        _;
    }

    constructor(address initialOracle) {
        require(initialOracle != address(0), "ProtegoGuard: oracle required");
        oracle = initialOracle;
        _nextId = 1;
    }

    /// @notice Owner can update oracle address
    function setOracle(address newOracle) external onlyOwner {
        require(newOracle != address(0), "ProtegoGuard: zero oracle");
        emit OracleUpdated(oracle, newOracle);
        oracle = newOracle;
    }

    /**
     * @notice Register a pending transaction's metadata for on-chain forensic logging.
     * @dev calldataData should be supplied by the client (e.g., frontend) and may be truncated
     *      if too large. We store calldata as bytes but audits should confirm size expectations.
     */
    function registerPendingTx(
        address target,
        uint256 value,
        bytes calldata calldataData,
        uint256 gasPrice,
        uint256 maxSlippageBps,
        string calldata notes
    ) external whenNotPaused nonReentrant returns (uint256) {
        if (calldataData.length == 0) revert EmptyCalldata();
        uint256 id = _nextId++;
        PendingTx storage p = _pendingTxs[id];
        p.id = id;
        p.submitter = msg.sender;
        p.target = target;
        p.value = value;
        p.calldataData = calldataData;
        p.gasPrice = gasPrice;
        p.maxSlippageBps = maxSlippageBps;
        p.timestamp = block.timestamp;
        p.protectedFlag = false;
        p.notes = notes;

        emit PendingTxRegistered(id, msg.sender, target);
        return id;
    }

    /**
     * @notice Oracle (off-chain detection engine) calls this to attach an alert to a registered tx.
     */
    function raiseAlert(
        uint256 pendingTxId,
        RiskLevel risk,
        uint256 confidence,
        string calldata reason
    ) external onlyOracle whenNotPaused returns (bool) {
        PendingTx storage p = _pendingTxs[pendingTxId];
        if (p.id == 0) revert InvalidId();
        Alert memory a = Alert({
            pendingTxId: pendingTxId,
            risk: risk,
            confidence: confidence,
            reason: reason,
            timestamp: block.timestamp,
            reporter: msg.sender
        });
        _alertsByTxId[pendingTxId].push(a);
        emit AlertRaised(pendingTxId, risk, confidence, reason, msg.sender);
        return true;
    }

    /**
     * @notice Mark a transaction as protected and store an optional short proof (e.g., relay tx hash or note).
     * @dev Only the original submitter or owner can mark a tx protected — the actual private submission
     *      must be done off-chain (Flashbots Protect or similar). This is only an on-chain record.
     */
    function markProtected(uint256 pendingTxId, string calldata proof) external whenNotPaused nonReentrant returns (bool) {
        PendingTx storage p = _pendingTxs[pendingTxId];
        if (p.id == 0) revert InvalidId();
        require(msg.sender == p.submitter || msg.sender == owner(), "ProtegoGuard: not allowed");
        p.protectedFlag = true;
        emit TransactionProtected(pendingTxId, msg.sender, proof);
        return true;
    }

    /* ----------------------------------------------------------------------
     * Views
     * ---------------------------------------------------------------------- */

    function getPendingTx(uint256 id) external view returns (
        uint256 pid,
        address submitter,
        address target,
        uint256 value,
        bytes memory calldataData,
        uint256 gasPrice,
        uint256 maxSlippageBps,
        uint256 timestamp,
        bool protectedFlag,
        string memory notes
    ) {
        PendingTx storage p = _pendingTxs[id];
        require(p.id != 0, "ProtegoGuard: unknown id");
        return (
            p.id,
            p.submitter,
            p.target,
            p.value,
            p.calldataData,
            p.gasPrice,
            p.maxSlippageBps,
            p.timestamp,
            p.protectedFlag,
            p.notes
        );
    }

    function getAlerts(uint256 id) external view returns (Alert[] memory) {
        return _alertsByTxId[id];
    }

    /* ----------------------------------------------------------------------
     * Utilities for owner
     * ---------------------------------------------------------------------- */

    /// @notice Emergency function: remove a stored pending tx (admin only). Keeps an on-chain audit trail via event.
    function adminRemovePendingTx(uint256 id) external onlyOwner {
        PendingTx storage p = _pendingTxs[id];
        require(p.id != 0, "ProtegoGuard: unknown id");
        delete _pendingTxs[id];
        // Emit a standardized event for audits (re-uses existing event)
        emit PendingTxRegistered(id, address(0), address(0));
    }

    /// @notice Owner can withdraw accidental ETH sent to the contract.
    function withdraw(address payable to, uint256 amount) external onlyOwner nonReentrant {
        require(to != address(0), "ProtegoGuard: zero address");
        (bool sent,) = to.call{value: amount}('');
        require(sent, "ProtegoGuard: withdraw failed");
    }

    // Allow contract to receive ETH for completeness (but not required)
    receive() external payable {}
}
