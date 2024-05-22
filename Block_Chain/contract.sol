// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TransactionHandler {
    struct Transaction {
        address sender;
        address receiver;
        string messageText;
        string fileHash;
        uint256 timestamp;
    }

    // Mapping from transaction ID to Transaction struct
    mapping(bytes32 => Transaction) public transactions;

    // Event to emit when a transaction is stored
    event TransactionStored(
        bytes32 indexed transactionId,
        address indexed sender,
        address indexed receiver,
        string messageText,
        string fileHash,
        uint256 timestamp
    );

    // Function to store a new transaction
    function storeTransaction(
        address _receiver,
        string memory _messageText,
        string memory _fileHash,
        uint256 _timestamp
    ) public returns (bytes32) {
        // Create a unique hash for the transaction
        bytes32 transactionId = keccak256(
            abi.encodePacked(msg.sender, _receiver, _messageText, _fileHash, _timestamp)
        );

        // Store the transaction in the mapping
        transactions[transactionId] = Transaction(
            msg.sender,
            _receiver,
            _messageText,
            _fileHash,
            _timestamp
        );

        // Emit an event for the stored transaction
        emit TransactionStored(transactionId, msg.sender, _receiver, _messageText, _fileHash, _timestamp);

        return transactionId;
    }

    // Function to retrieve a transaction
    function getTransaction(bytes32 _transactionId) public view returns (Transaction memory) {
        return transactions[_transactionId];
    }
}
