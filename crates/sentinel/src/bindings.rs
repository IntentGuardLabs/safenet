use safenet_core::watcher_events;

#[allow(clippy::too_many_arguments)]
pub mod oracle {
    use alloy::sol;

    sol! {
        // Mirrors `SentinelOracleRequest.State` in
        // `contracts/src/libraries/SentinelOracleRequests.sol`; `DisputeResolved.outcome` is
        // this type. Declaration order must match the Solidity enum exactly -- `sol!` decodes by
        // ordinal position, not by name. `NONE` is a zero-value sentinel the contract never
        // actually emits (it means "request was never created"), included here only to keep the
        // ordinals of every other variant aligned with the real enum.
        #[derive(Debug, PartialEq, Eq)]
        enum RequestState {
            NONE,
            PENDING,
            FROZEN,
            RESOLVED_APPROVED,
            RESOLVED_DENIED,
            TIMED_OUT
        }

        #[derive(Debug)]
        contract SentinelOracle {
            event NewRequest(
                bytes32 indexed requestId,
                address indexed sponsor,
                uint96 fee,
                uint96 bondTarget,
                uint24 daoFeeShare,
                uint96 slashAmount,
                uint64 commitDeadline,
                uint64 revealDeadline
            );
            event Committed(bytes32 indexed requestId, address indexed sentinel, uint96 bondAmount);
            event Revealed(
                bytes32 indexed requestId,
                address indexed sentinel,
                bool approved,
                uint96 bondAmount,
                string reason
            );
            event DisputeTriggered(bytes32 indexed requestId, uint64 deadline);
            event DisputeResolved(bytes32 indexed requestId, RequestState outcome, uint128 slashed, string context);
            event RequestTimedOut(bytes32 indexed requestId);
            event OracleResult(bytes32 indexed requestId, address indexed sponsor, bytes result, bool approved);
            event ArbitrationTimedOut(bytes32 indexed requestId);
            event DisputeOutOfScope(bytes32 indexed requestId, string context);
            event Claimed(bytes32 indexed requestId, address indexed sentinel, uint96 bondReturn, uint96 feeReward);

            function commit(bytes32 requestId, bytes32 commitHash) external;
            function reveal(bytes32 requestId, bool approve, bytes32 salt, string calldata reason) external;
            function hashCommitment(
                address sentinel,
                bytes32 requestId,
                bool approve,
                bytes32 salt,
                string calldata reason
            ) external pure returns (bytes32);
            function finalize(bytes32 requestId) external;
            function claim(bytes32 requestId) external;
            function timeoutArbitration(bytes32 requestId) external;
        }

        #[derive(Debug)]
        contract ERC20 {
            function approve(address spender, uint256 amount) external returns (bool);
            function allowance(address owner, address spender) external view returns (uint256);
        }
    }
}

pub mod consensus {
    use alloy::sol;
    use serde::{Serialize, Serializer, ser};

    sol! {
        #[derive(Debug, Default, PartialEq, Eq)]
        enum Operation { #[default] CALL, DELEGATECALL }

        // Full transaction struct carried by TransactionProposed; mirrors SafeTransaction.T.
        #[derive(Debug, Default, PartialEq, Eq, Serialize)]
        struct SafeTransaction {
            uint256 chainId;
            address safe;
            address to;
            uint256 value;
            bytes data;
            Operation operation;
            uint256 safeTxGas;
            uint256 baseGas;
            uint256 gasPrice;
            address gasToken;
            address refundReceiver;
            uint256 nonce;
        }

        // EIP-712 struct for the oracle requestId.
        // Field order and types must exactly match the onchain typehash in ConsensusMessages.sol:
        // keccak256("TransactionProposal(uint64 epoch,address oracle,bytes oracleData,bytes32 safeTxHash)")
        // Domain: { chainId, verifyingContract: consensus }
        #[derive(Debug)]
        struct TransactionProposal {
            uint64 epoch;
            address oracle;
            bytes oracleData;
            bytes32 safeTxHash;
        }

        #[derive(Debug)]
        contract Consensus {
            event TransactionProposed(
                bytes32 indexed safeTxHash,
                bytes32 indexed safeId,
                address indexed oracle,
                uint64 epoch,
                bytes oracleData,
                SafeTransaction transaction
            );
        }
    }

    impl Serialize for Operation {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let code = match self {
                Operation::CALL => 0,
                Operation::DELEGATECALL => 1,
                _ => return Err(ser::Error::custom("invalid Safe transaction operation")),
            };
            serializer.serialize_u8(code)
        }
    }
}

// Safe EIP-712 signing type, separate from the Safenet contract ABI bindings above.
pub mod safe {
    use alloy::sol;

    sol! {
        #[derive(Debug)]
        enum Operation { CALL, DELEGATECALL }

        // EIP-712 struct for the Safe transaction struct hash.
        // Field order and types must exactly match the onchain typehash in SafeTransaction.sol:
        // keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,
        //   uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")
        // Domain: { chainId, verifyingContract: safe }
        #[derive(Debug)]
        struct SafeTx {
            address to;
            uint256 value;
            bytes data;
            Operation operation;
            uint256 safeTxGas;
            uint256 baseGas;
            uint256 gasPrice;
            address gasToken;
            address refundReceiver;
            uint256 nonce;
        }
    }
}

// The event set consumed by the Watcher and StateMachine: all events from
// both the SentinelOracle and Consensus contracts.
watcher_events! {
    #[derive(Debug)]
    pub enum SentinelEvents {
        Oracle(oracle::SentinelOracle::SentinelOracleEvents),
        Consensus(consensus::Consensus::ConsensusEvents),
    }
}

#[cfg(test)]
mod tests {
    use super::{consensus::Consensus, oracle::SentinelOracle};
    use alloy::{primitives::b256, sol_types::SolEvent};

    /// The event topics the sentinel filters on must equal the topics the deployed contracts
    /// emit, or the watcher silently never sees those events: an event whose signature differs
    /// (for example a missing `daoFeeShare` on `NewRequest`) is excluded by the log filter with
    /// no error, and the sentinel then never opens the request it holds a verdict for.
    ///
    /// The expected hashes are the keccak256 of the signatures in `contracts/src` and were
    /// cross-checked against the topics emitted by the deployed Gnosis testnet contracts.
    /// Changing one of these means the contract's event changed: update the binding with it.
    #[test]
    fn event_topics_match_the_deployed_contracts() {
        assert_eq!(
            SentinelOracle::NewRequest::SIGNATURE_HASH,
            b256!("8ec61272960f97d43d7f8f85ed630aa512818577f3d1e548e7627b06dbbbda86"),
        );
        assert_eq!(
            SentinelOracle::Committed::SIGNATURE_HASH,
            b256!("45acbf2626c7d2bd97eb2142a43d392e8f3364c9e140b3d022446155491819d6"),
        );
        assert_eq!(
            SentinelOracle::Revealed::SIGNATURE_HASH,
            b256!("d2cdead965dbd376703d9a79240f31f1228055ab42384b68353332fcd2af939a"),
        );
        assert_eq!(
            SentinelOracle::Claimed::SIGNATURE_HASH,
            b256!("006f1d9d8ec7f5d7941e2363561ba0f1da911361b351d007f9b448d557e39e86"),
        );
        assert_eq!(
            SentinelOracle::RequestTimedOut::SIGNATURE_HASH,
            b256!("f1ca1e9147be737b04a2b018a79405f687a97de8dd8a2559bbe62357343af414"),
        );
        assert_eq!(
            SentinelOracle::OracleResult::SIGNATURE_HASH,
            b256!("7843c453c4f7442b00e1bf3873e741f18f3447e18a13304c58bef95efd311757"),
        );
        assert_eq!(
            SentinelOracle::DisputeTriggered::SIGNATURE_HASH,
            b256!("86e8b85731e4787f033d85108356db1e068dea243be32d422e6dc5681ff49cc1"),
        );
        assert_eq!(
            SentinelOracle::ArbitrationTimedOut::SIGNATURE_HASH,
            b256!("5f19817b3ad988fdb5a7fb3f657a755e58a107bf47431574b7c516a6dc1551e6"),
        );
        assert_eq!(
            Consensus::TransactionProposed::SIGNATURE_HASH,
            b256!("47d867ce4d91d0487fa4d2ac80b13e7466ce53dd018a8eef564fc60c92b53d03"),
        );
    }
}
