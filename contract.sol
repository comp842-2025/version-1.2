// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CertificateRegistry {
    address public owner;
    mapping(address => bool) public admins;
    uint256 public adminCount;

    uint256 public constant MAX_DETAILS_LEN = 2000;
    uint256 public constant MAX_NOTES_LEN   = 2000;

    struct Certificate {
        string  productName;
        string  mfgName;
        uint256 mfgDate;
        uint256 expDate;
        string  location;
        string  intendedRegion;
        string  details;
        string  notes;
        bool    isValid;
    }

    mapping(string => Certificate) private _certs;
    mapping(string => address)     public certificateOwners;

    event AdminAdded(address indexed newAdmin, address indexed addedBy);
    event AdminRemoved(address indexed removedAdmin, address indexed removedBy);

    event CertificateIssued(
        string indexed certId,
        string productName,
        string mfgName,
        uint256 mfgDate,
        uint256 expDate,
        string location,
        string intendedRegion,
        string details,
        string notes
    );

    event CertificateRevoked(string indexed certId);
    event CertificateTransferred(string indexed certId, address indexed from, address indexed to);
    event CertificateMetadataUpdated(string indexed certId);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    modifier onlyAdmin() {
        require(admins[msg.sender], "Only admin");
        _;
    }

    constructor() {
        owner = msg.sender;
        admins[msg.sender] = true;
        adminCount = 1;
    }

    // ---------------- Owner controls ----------------
    function addAdmin(address newAdmin) external onlyOwner {
        require(newAdmin != address(0), "Invalid address");
        require(!admins[newAdmin], "Already admin");
        admins[newAdmin] = true;
        adminCount++;
        emit AdminAdded(newAdmin, msg.sender);
    }

    function removeAdmin(address adminToRemove) external onlyOwner {
        require(admins[adminToRemove], "Not an admin");
        require(adminToRemove != owner, "Cannot remove owner");
        admins[adminToRemove] = false;
        adminCount--;
        emit AdminRemoved(adminToRemove, msg.sender);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid address");
        require(newOwner != owner, "Same owner");
        admins[owner] = false;
        admins[newOwner] = true;
        owner = newOwner;
    }

    // ---------------- Issue / Revoke ----------------
    function issueCertificate(
        string memory certId,
        string memory productName,
        string memory mfgName,
        uint256 mfgDate,
        uint256 expDate,
        string  memory location,
        string  memory intendedRegion,
        string  memory details,
        string  memory notes
    ) external onlyAdmin {
        require(bytes(certId).length > 0, "Cert ID empty");
        require(bytes(productName).length > 0, "Product empty");
        require(bytes(mfgName).length > 0, "Manufacturer empty");
        require(bytes(_certs[certId].productName).length == 0, "Cert ID exists");
        require(expDate == 0 || expDate > mfgDate, "Expiry <= mfgDate");
        require(bytes(details).length <= MAX_DETAILS_LEN, "Details too long");
        require(bytes(notes).length <= MAX_NOTES_LEN, "Notes too long");

        _certs[certId] = Certificate({
            productName: productName,
            mfgName: mfgName,
            mfgDate: mfgDate,
            expDate: expDate,
            location: location,
            intendedRegion: intendedRegion,
            details: details,
            notes: notes,
            isValid: true
        });

        // first owner = issuing admin
        certificateOwners[certId] = msg.sender;

        emit CertificateIssued(
            certId, productName, mfgName, mfgDate, expDate, location, intendedRegion, details, notes
        );
    }

    function revokeCertificate(string memory certId) external onlyAdmin {
        require(bytes(_certs[certId].productName).length > 0, "Cert not exist");
        _certs[certId].isValid = false;
        emit CertificateRevoked(certId);
    }

    function updateCertificateMetadata(
        string memory certId,
        uint256 expDate,
        string  memory location,
        string  memory intendedRegion,
        string  memory details,
        string  memory notes
    ) external {
        require(bytes(_certs[certId].productName).length > 0, "Cert not exist");
        require(
            msg.sender == certificateOwners[certId] || admins[msg.sender],
            "Only owner or admin"
        );
        require(bytes(details).length <= MAX_DETAILS_LEN, "Details too long");
        require(bytes(notes).length <= MAX_NOTES_LEN, "Notes too long");

        if (expDate != 0) {
            require(expDate > _certs[certId].mfgDate, "Bad expiry");
            _certs[certId].expDate = expDate;
        }
        if (bytes(location).length > 0)       _certs[certId].location = location;
        if (bytes(intendedRegion).length > 0) _certs[certId].intendedRegion = intendedRegion;
        if (bytes(details).length > 0)        _certs[certId].details = details;
        if (bytes(notes).length > 0)          _certs[certId].notes = notes;

        emit CertificateMetadataUpdated(certId);
    }

    // ---------------- Transfers ----------------
    function transferCertificate(string calldata certId, address to) external {
        require(to != address(0), "Invalid recipient");
        Certificate memory c = _certs[certId];
        require(bytes(c.productName).length > 0, "Cert not exist");
        require(c.isValid, "Cert revoked");

        address from = certificateOwners[certId];
        require(from != address(0), "No owner");
        require(msg.sender == from, "Only cert owner");

        certificateOwners[certId] = to;
        emit CertificateTransferred(certId, from, to);
    }

    // ---------------- Views ----------------
    function getCertificate(string memory certId)
        external
        view
        returns (string memory productName, string memory mfgName, uint256 mfgDate, bool isValid)
    {
        Certificate memory c = _certs[certId];
        return (c.productName, c.mfgName, c.mfgDate, c.isValid);
    }

    function getCertificateFull(string memory certId)
        external
        view
        returns (
            string memory productName,
            string memory mfgName,
            uint256 mfgDate,
            uint256 expDate,
            string  memory location,
            string  memory intendedRegion,
            string  memory details,
            string  memory notes,
            bool    isValid
        )
    {
        Certificate memory c = _certs[certId];
        return (c.productName, c.mfgName, c.mfgDate, c.expDate, c.location, c.intendedRegion, c.details, c.notes, c.isValid);
    }

    function ownerOfCertificate(string calldata certId) external view returns (address) {
        return certificateOwners[certId];
    }

    function isAdmin(address account) external view returns (bool) {
        return admins[account];
    }

    function getAllAdminInfo()
        external
        view
        returns (uint256 totalAdmins, bool isCallerAdmin, bool isCallerOwner)
    {
        return (adminCount, admins[msg.sender], msg.sender == owner);
    }
}
