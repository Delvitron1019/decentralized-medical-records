// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title MedicalRecords
 * @notice Patient-controlled access to medical record pointers.
 *
 * THE CENTRAL DESIGN DECISION
 * --------------------------
 * No patient data is stored on-chain. Only a content hash (an IPFS CID or
 * equivalent) plus metadata. This is not an optimisation, it is the whole
 * point: on-chain data is permanent, world-readable, and cannot be deleted.
 * Putting PHI there would be irreversible and, under GDPR's right to erasure
 * or HIPAA, unlawful. The chain stores *who may access what*; the encrypted
 * payload lives off-chain.
 *
 * WHO CAN DO WHAT
 * ---------------
 *   Patient   owns their record set. Grants and revokes access. The only
 *             party who can authorise a hospital to write or an insurer to
 *             read.
 *   Hospital  writes records for a patient who has granted write access.
 *             Cannot read records it did not author unless granted.
 *   Insurer   read-only, and only for records a patient has explicitly
 *             shared. Never granted blanket access.
 *   Admin     assigns and revokes the HOSPITAL and INSURER roles, and can
 *             pause the contract. Deliberately cannot read records — an
 *             administrator is not a clinician.
 *
 * WHAT REVOCATION DOES AND DOES NOT DO
 * ------------------------------------
 * Revoking access stops future reads of the pointer. It cannot un-read data
 * already fetched and decrypted, and it cannot claw back a copy. Any system
 * claiming otherwise is misrepresenting what a blockchain can enforce. Real
 * revocation requires off-chain key rotation and re-encryption; this contract
 * only enforces the authorisation layer.
 */
contract MedicalRecords is AccessControl, Pausable {
    bytes32 public constant HOSPITAL_ROLE = keccak256("HOSPITAL_ROLE");
    bytes32 public constant INSURER_ROLE  = keccak256("INSURER_ROLE");

    enum RecordType { Diagnosis, LabResult, Imaging, Prescription, DischargeSummary }

    struct Record {
        bytes32     contentHash;   // IPFS CID or hash of the encrypted payload
        address     author;        // hospital that wrote it
        uint64      createdAt;
        RecordType  recordType;
        bool        exists;
    }

    enum Permission { None, Read, Write }

    // patient => recordId => Record
    mapping(address => mapping(uint256 => Record)) private _records;
    // patient => number of records
    mapping(address => uint256) public recordCount;
    // patient => grantee => permission
    mapping(address => mapping(address => Permission)) private _permissions;
    // patient => recordId => grantee => explicitly shared
    mapping(address => mapping(uint256 => mapping(address => bool))) private _recordShares;

    event RecordAdded(address indexed patient, uint256 indexed recordId,
                      address indexed author, RecordType recordType, bytes32 contentHash);
    event AccessGranted(address indexed patient, address indexed grantee, Permission permission);
    event AccessRevoked(address indexed patient, address indexed grantee);
    event RecordShared(address indexed patient, uint256 indexed recordId, address indexed grantee);
    event RecordShareRevoked(address indexed patient, uint256 indexed recordId, address indexed grantee);

    error NotAuthorized(address caller, address patient);
    error RecordNotFound(address patient, uint256 recordId);
    error CannotGrantToSelf();
    error InvalidPermission();

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    // ── Patient controls ────────────────────────────────────────────────────

    /**
     * @notice Grant a hospital write access or an insurer read access.
     * @dev Callable only by the patient themselves. There is intentionally no
     *      admin override: an administrator who can grant themselves access to
     *      any record defeats the purpose of the design.
     */
    function grantAccess(address grantee, Permission permission) external whenNotPaused {
        if (grantee == msg.sender) revert CannotGrantToSelf();
        if (permission == Permission.None) revert InvalidPermission();
        _permissions[msg.sender][grantee] = permission;
        emit AccessGranted(msg.sender, grantee, permission);
    }

    function revokeAccess(address grantee) external {
        // Deliberately callable while paused. A patient must always be able to
        // withdraw consent, even if the contract is otherwise frozen.
        _permissions[msg.sender][grantee] = Permission.None;
        emit AccessRevoked(msg.sender, grantee);
    }

    /// @notice Share one specific record, rather than the whole history.
    function shareRecord(uint256 recordId, address grantee) external whenNotPaused {
        if (!_records[msg.sender][recordId].exists) {
            revert RecordNotFound(msg.sender, recordId);
        }
        _recordShares[msg.sender][recordId][grantee] = true;
        emit RecordShared(msg.sender, recordId, grantee);
    }

    function revokeRecordShare(uint256 recordId, address grantee) external {
        _recordShares[msg.sender][recordId][grantee] = false;
        emit RecordShareRevoked(msg.sender, recordId, grantee);
    }

    // ── Hospital writes ─────────────────────────────────────────────────────

    function addRecord(address patient, bytes32 contentHash, RecordType recordType)
        external
        onlyRole(HOSPITAL_ROLE)
        whenNotPaused
        returns (uint256 recordId)
    {
        if (_permissions[patient][msg.sender] != Permission.Write) {
            revert NotAuthorized(msg.sender, patient);
        }
        recordId = recordCount[patient];
        _records[patient][recordId] = Record({
            contentHash: contentHash,
            author:      msg.sender,
            createdAt:   uint64(block.timestamp),
            recordType:  recordType,
            exists:      true
        });
        recordCount[patient] = recordId + 1;
        emit RecordAdded(patient, recordId, msg.sender, recordType, contentHash);
    }

    // ── Reads ───────────────────────────────────────────────────────────────

    /**
     * @notice Fetch a record pointer.
     * @dev Access is allowed if the caller is the patient, holds a standing
     *      Read or Write grant, authored the record, or was given a
     *      record-level share. Anything else reverts.
     *
     *      This is a view function, so enforcement here is advisory against a
     *      determined observer: anyone can read contract storage directly off
     *      a public chain. The confidentiality guarantee comes from the
     *      payload being encrypted off-chain, not from this check. The check
     *      exists so that honest clients cannot accidentally over-reach, and
     *      so the authorisation state is itself auditable.
     */
    function getRecord(address patient, uint256 recordId)
        external
        view
        returns (bytes32 contentHash, address author, uint64 createdAt, RecordType recordType)
    {
        Record storage r = _records[patient][recordId];
        if (!r.exists) revert RecordNotFound(patient, recordId);
        if (!_canRead(patient, recordId, msg.sender)) {
            revert NotAuthorized(msg.sender, patient);
        }
        return (r.contentHash, r.author, r.createdAt, r.recordType);
    }

    function _canRead(address patient, uint256 recordId, address caller)
        internal view returns (bool)
    {
        if (caller == patient) return true;
        if (_records[patient][recordId].author == caller) return true;
        if (_recordShares[patient][recordId][caller]) return true;
        Permission p = _permissions[patient][caller];
        return p == Permission.Read || p == Permission.Write;
    }

    function permissionOf(address patient, address grantee) external view returns (Permission) {
        return _permissions[patient][grantee];
    }

    function isRecordSharedWith(address patient, uint256 recordId, address grantee)
        external view returns (bool)
    {
        return _recordShares[patient][recordId][grantee];
    }

    // ── Admin ───────────────────────────────────────────────────────────────

    function pause()   external onlyRole(DEFAULT_ADMIN_ROLE) { _pause();   }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }
}
