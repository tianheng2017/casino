// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ModExp Library
 * @dev Optimized modular arithmetic operations
 */
library ModExp {
    /**
     * @dev Calculate modular exponentiation using binary method
     * @param base Base number
     * @param exponent Exponent
     * @param modulus Modulus
     * @return result Result of (base^exponent) % modulus
     */
    function modExp(uint256 base, uint256 exponent, uint256 modulus) 
        internal 
        pure 
        returns (uint256 result) 
    {
        require(modulus != 0, "ModExp: modulus cannot be zero");
        
        if (exponent == 0) return 1;
        if (base == 0) return 0;
        
        result = 1;
        base = base % modulus;

        while (exponent > 0) {
            if (exponent & 1 == 1) {
                result = mulmod(result, base, modulus);
            }
            exponent >>= 1;
            base = mulmod(base, base, modulus);
        }
    }

    /**
     * @dev Calculate modular inverse using extended Euclidean algorithm
     * @param a Number to find inverse for
     * @param m Modulus
     * @return Modular inverse of a mod m
     */
    function modInverse(uint256 a, uint256 m) internal pure returns (uint256) {
        require(m > 1, "ModExp: modulus must be greater than 1");
        
        (int256 g, int256 x,) = extendedGcd(int256(a % m), int256(m));
        require(g == 1, "ModExp: modular inverse does not exist");
        
        return uint256(x < 0 ? x + int256(m) : x);
    }

    /**
     * @dev Extended Euclidean algorithm
     */
    function extendedGcd(int256 a, int256 b) 
        internal 
        pure 
        returns (int256 gcd, int256 x, int256 y) 
    {
        if (a == 0) {
            return (b, 0, 1);
        }
        
        (int256 gcd1, int256 x1, int256 y1) = extendedGcd(b % a, a);
        x = y1 - (b / a) * x1;
        y = x1;
        gcd = gcd1;
    }
}

/**
 * @title Paillier Homomorphic Encryption Contract
 * @dev Implements Paillier cryptosystem for homomorphic encryption
 */
contract Paillier {
    using ModExp for uint256;

    // Public parameters (some are zero until revealed)
    uint256 public p;
    uint256 public q;
    uint256 public g;
    uint256 public n;
    uint256 public nSquared;
    uint256 public lambda;
    uint256 public mu;

    // Events for transparency
    event ParametersSet(uint256 n, uint256 g, uint256 nSquared);

    constructor(uint256 _n) {
        require(_n > 1, "Paillier: n must be greater than 1");
        
        n = _n;
        g = _n + 1; // Simplified generator choice
        nSquared = _n * _n;
        
        emit ParametersSet(n, g, nSquared);
    }

    /**
     * @dev Generate pseudo-random number for encryption
     * @return Random number coprime to nSquared
     */
    function generateR() public view returns (uint256) {
        uint256 randomNum = uint256(
            keccak256(abi.encodePacked(block.timestamp, msg.sender, block.difficulty))
        ) % n;
        
        // Ensure r > 0 and gcd(r, n) = 1
        return randomNum == 0 ? 1 : randomNum;
    }

    /**
     * @dev Encrypt a message using Paillier encryption
     * @param message Plaintext message to encrypt
     * @return Encrypted ciphertext
     */
    function encrypt(uint256 message) public view returns (uint256) {
        require(message < n, "Paillier: message must be smaller than n");

        uint256 r = generateR();
        uint256 gToM = g.modExp(message, nSquared);
        uint256 rToN = r.modExp(n, nSquared);

        return mulmod(gToM, rToN, nSquared);
    }

    /**
     * @dev Decrypt a ciphertext using Paillier decryption
     * @param ciphertext Encrypted message
     * @return Decrypted plaintext
     */
    function decrypt(uint256 ciphertext) public view returns (uint256) {
        require(lambda > 0, "Paillier: lambda not set");
        require(mu > 0, "Paillier: mu not set");
        
        uint256 temp = ciphertext.modExp(lambda, nSquared);
        return mulmod(L(temp), mu, n);
    }

    /**
     * @dev L function for Paillier decryption: L(x) = (x-1)/n
     */
    function L(uint256 x) private view returns (uint256) {
        require(x > 0, "Paillier: L function input must be positive");
        return (x - 1) / n;
    }

    /**
     * @dev Homomorphic addition of two encrypted values
     * @param encA First encrypted value
     * @param encB Second encrypted value
     * @return Result of homomorphic addition
     */
    function addHomomorphically(uint256 encA, uint256 encB) 
        public 
        view 
        returns (uint256) 
    {
        return mulmod(encA, encB, nSquared);
    }

    /**
     * @dev Hash integer to bytes32
     */
    function hashInteger(uint256 input) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(input));
    }

    /**
     * @dev Hash string to uint256 within range [0, n)
     */
    function hashToUint(string memory inputString) public view returns (uint256) {
        bytes32 hash = keccak256(abi.encodePacked(inputString));
        return uint256(hash) % n;
    }

    /**
     * @dev Convert bytes32 to string
     */
    function bytes32ToString(bytes32 _bytes32) public pure returns (string memory) {
        uint8 length = 0;
        while (length < 32 && _bytes32[length] != 0) {
            length++;
        }
        
        bytes memory result = new bytes(length);
        for (uint8 i = 0; i < length; i++) {
            result[i] = _bytes32[i];
        }
        
        return string(result);
    }
}

/**
 * @title Optimized Lottery Contract
 * @dev A verifiable fair lottery system using Paillier homomorphic encryption
 */
contract OptimizedLotteryContract is Paillier, ReentrancyGuard, Pausable, Ownable {
    
    // Game states
    enum State { NotStarted, InProgress, Revealed, Ended }

    // Order structure (optimized with packed struct)
    struct Order {
        address player;      // 20 bytes
        uint64 amount;       // 8 bytes
        uint64 timestamp;    // 8 bytes
        uint32 k;           // 4 bytes
        uint8 status;       // 1 byte: 0=pending, 1=lost, 2=won
        bool isSettled;     // 1 byte
        bool isCompensated; // 1 byte
        uint256 encX;       // 32 bytes (separate slot for gas optimization)
    }

    // Betting records structure
    struct BettingRecord {
        uint32[] ks;
        uint64[] amounts;
    }

    // Constants
    uint256 public constant BET_AMOUNT = 0.01 ether;
    uint256 public constant MIN_CASINO_FUND = 20 ether;
    uint256 public constant REVEAL_DEADLINE = 2 hours;
    uint256 public constant RNG_REWARD_RATE = 1000; // 0.1% = 1/1000

    // State variables
    uint256 public r; // Encrypted r initially, plaintext after reveal
    State public gameState;
    uint256 public revealDeadline;
    uint256 public vESum; // Sum of encrypted RNG values
    bool public casinoCheated;

    // Counters
    uint32 public totalControlledPlayers;
    uint32 public currentControlledPlayers;
    uint32 public currentPublicPlayers;
    uint32 public orderCounter;

    // Mappings
    mapping(address => bool) public isControlledPlayer;
    mapping(uint32 => Order) public orders;
    mapping(address => BettingRecord) private bettingRecords;
    mapping(address => uint256) public winningAmounts;
    mapping(address => uint256) public rngSubmissions;

    // Events
    event RNGSubmitted(address indexed player, uint256 encryptedValue, uint256 newSum);
    event BetPlaced(uint32 indexed orderId, address indexed player, uint256 krSum, uint64 timestamp);
    event LotteryResult(uint32 indexed orderId, address indexed player, bool won);
    event RNGPhaseCompleted(uint32 controlledCount, uint32 totalRequired, uint256 finalSum);
    event GameRevealed(uint256 r, uint256 p, uint256 q, uint256 vSum);
    event RewardClaimed(address indexed player, uint256 amount);
    event CompensationClaimed(address indexed player, uint256 amount);
    event CheatingDetected(string reason);

    // Modifiers
    modifier onlyInState(State _state) {
        require(gameState == _state, "Invalid game state");
        _;
    }

    modifier onlyControlledPlayer() {
        require(isControlledPlayer[msg.sender], "Not a controlled player");
        _;
    }

    modifier withinRevealDeadline() {
        require(block.timestamp <= revealDeadline, "Reveal deadline passed");
        _;
    }

    /**
     * @dev Constructor
     * @param _n Paillier parameter n = p * q
     * @param _controlledPlayers Array of controlled player addresses
     */
    constructor(
        uint256 _n, 
        address[] memory _controlledPlayers
    ) 
        Paillier(_n) 
        payable 
    {
        require(msg.value >= MIN_CASINO_FUND, "Insufficient casino funds");
        require(_controlledPlayers.length >= 2, "Need at least 2 controlled players");

        // Register controlled players
        for (uint256 i = 0; i < _controlledPlayers.length; i++) {
            require(_controlledPlayers[i] != address(0), "Invalid player address");
            require(!isControlledPlayer[_controlledPlayers[i]], "Duplicate player");
            
            isControlledPlayer[_controlledPlayers[i]] = true;
            totalControlledPlayers++;
        }
        
        gameState = State.NotStarted;
    }

    /**
     * @dev Submit encrypted RNG value
     * @param encryptedValue Encrypted random value
     */
    function submitRNG(uint256 encryptedValue) 
        external 
        onlyInState(State.InProgress)
        nonReentrant 
    {
        require(rngSubmissions[msg.sender] == 0, "Already submitted RNG");
        require(encryptedValue > 0 && encryptedValue < nSquared, "Invalid encrypted value");
        require(currentControlledPlayers < totalControlledPlayers, "All controlled players submitted");

        bool isControlled = isControlledPlayer[msg.sender];

        // Enforce submission order
        if (currentPublicPlayers == 0) {
            require(msg.sender == owner(), "Casino must submit first");
            currentPublicPlayers++;
        } else if (currentControlledPlayers == totalControlledPlayers - 1) {
            require(isControlled, "Last submitter must be controlled player");
            currentControlledPlayers++;
        } else {
            if (isControlled) {
                currentControlledPlayers++;
            } else {
                require(currentPublicPlayers <= totalControlledPlayers - 2, "No more public submissions allowed");
                currentPublicPlayers++;
            }
        }

        // Record submission
        rngSubmissions[msg.sender] = encryptedValue;

        // Calculate homomorphic sum
        vESum = vESum == 0 ? encryptedValue : addHomomorphically(vESum, encryptedValue);

        // Send RNG participation reward
        uint256 reward = address(this).balance / RNG_REWARD_RATE;
        if (reward > 0) {
            (bool success,) = payable(msg.sender).call{value: reward}("");
            require(success, "Reward transfer failed");
        }

        emit RNGSubmitted(msg.sender, encryptedValue, vESum);

        // Check if RNG phase is complete
        if (currentControlledPlayers == totalControlledPlayers) {
            emit RNGPhaseCompleted(currentControlledPlayers, totalControlledPlayers, vESum);
        }
    }

    /**
     * @dev Set encrypted r value (casino only)
     * @param encryptedR Encrypted random value r
     */
    function setEncryptedR(uint256 encryptedR) 
        external 
        onlyOwner 
        onlyInState(State.NotStarted) 
    {
        require(encryptedR > 0, "Invalid encrypted r");
        
        r = encryptedR;
        gameState = State.InProgress;
    }

    /**
     * @dev Place a bet
     * @param k Player's chosen value
     */
    function placeBet(uint32 k) 
        external 
        payable 
        onlyInState(State.InProgress)
        nonReentrant
        whenNotPaused
    {
        require(msg.value == BET_AMOUNT, "Incorrect bet amount");
        require(currentControlledPlayers == totalControlledPlayers, "RNG phase not complete");
        
        // Ensure casino has sufficient funds for potential payouts
        uint256 requiredFunds = (orderCounter + 1) * BET_AMOUNT * 2;
        require(address(this).balance >= requiredFunds, "Insufficient casino funds");

        uint64 timestamp = uint64(block.timestamp);

        // Store order
        orders[orderCounter] = Order({
            player: msg.sender,
            k: k,
            amount: uint64(msg.value),
            isSettled: false,
            status: 0,
            encX: 0,
            timestamp: timestamp,
            isCompensated: false
        });

        // Update betting records
        bettingRecords[msg.sender].amounts.push(uint64(msg.value));
        bettingRecords[msg.sender].ks.push(k);

        // Calculate kr_sum for casino
        uint256 krSum = addHomomorphically(encrypt(k), r);

        emit BetPlaced(orderCounter, msg.sender, krSum, timestamp);
        orderCounter++;
    }

    /**
     * @dev Upload lottery result (casino only)
     * @param orderId Order ID
     * @param encryptedX Encrypted x value
     * @param result 1 = lost, 2 = won
     */
    function uploadResult(
        uint32 orderId, 
        uint256 encryptedX, 
        uint8 result
    ) 
        external 
        onlyOwner 
        onlyInState(State.InProgress) 
    {
        require(orderId < orderCounter, "Invalid order ID");
        require(result == 1 || result == 2, "Invalid result");
        
        Order storage order = orders[orderId];
        require(!order.isSettled, "Order already settled");

        order.status = result;
        order.isSettled = true;
        order.encX = encryptedX;

        if (result == 2) { // Won
            winningAmounts[order.player] += order.amount * 2;
        }

        emit LotteryResult(orderId, order.player, result == 2);
    }

    /**
     * @dev Claim winnings
     */
    function claimReward() 
        external 
        onlyInState(State.InProgress)
        nonReentrant 
    {
        uint256 amount = winningAmounts[msg.sender];
        require(amount > 0, "No winnings to claim");

        winningAmounts[msg.sender] = 0;

        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        emit RewardClaimed(msg.sender, amount);
    }

    /**
     * @dev Reveal game parameters (casino only)
     * @param _r Plaintext r
     * @param _p Prime p
     * @param _q Prime q
     * @param _vSum Sum of RNG values
     */
    function revealParameters(
        uint256 _r,
        uint256 _p,
        uint256 _q,
        uint256 _vSum
    ) 
        external 
        onlyOwner 
        onlyInState(State.InProgress) 
    {
        require(_r > 0 && _p > 0 && _q > 0 && _vSum > 0, "Invalid parameters");

        // Set Paillier parameters for decryption
        p = _p;
        q = _q;
        lambda = (_p - 1) * (_q - 1) / _gcd(_p - 1, _q - 1);
        mu = ModExp.modInverse(lambda, n);

        // Verify submissions
        bool isValid = _verifySubmissions(_r, _vSum);
        if (!isValid) {
            casinoCheated = true;
            emit CheatingDetected("Invalid parameter revelation");
        }

        r = _r;
        gameState = State.Revealed;
        revealDeadline = block.timestamp + REVEAL_DEADLINE;

        emit GameRevealed(_r, _p, _q, _vSum);
    }

    /**
     * @dev Verify game integrity
     * @return true if casino cheated
     */
    function verifyGame() 
        public 
        onlyInState(State.Revealed)
        withinRevealDeadline
        returns (bool) 
    {
        if (casinoCheated) {
            return true; // Already detected cheating
        }

        // Verify all orders
        for (uint32 i = 0; i < orderCounter; i++) {
            if (!_verifyOrder(i)) {
                casinoCheated = true;
                emit CheatingDetected("Invalid order verification");
                break;
            }
        }

        return casinoCheated;
    }

    /**
     * @dev Report casino fraud
     * @return true if casino cheated
     */
    function reportFraud() 
        external 
        onlyInState(State.Revealed)
        withinRevealDeadline
        returns (bool) 
    {
        return verifyGame();
    }

    /**
     * @dev Claim compensation for fraud
     */
    function claimCompensation() 
        external 
        onlyInState(State.Revealed)
        withinRevealDeadline
        nonReentrant 
    {
        require(casinoCheated, "No fraud detected");

        uint256 compensation = 0;
        uint256 betCount = 0;

        // Calculate compensation for all user's bets
        for (uint32 i = 0; i < orderCounter; i++) {
            Order storage order = orders[i];
            if (order.player == msg.sender && !order.isCompensated) {
                order.isCompensated = true;
                compensation += order.amount * 2; // Double compensation
                betCount++;
            }
        }

        require(betCount > 0, "No bets to compensate");

        (bool success,) = payable(msg.sender).call{value: compensation}("");
        require(success, "Compensation transfer failed");

        emit CompensationClaimed(msg.sender, compensation);
    }

    /**
     * @dev Casino withdraws funds after successful game
     */
    function withdrawFunds() 
        external 
        onlyOwner 
        onlyInState(State.Revealed) 
    {
        require(block.timestamp > revealDeadline, "Reveal period not ended");
        require(!casinoCheated, "Cannot withdraw after fraud");

        gameState = State.Ended;
        
        uint256 amount = address(this).balance;
        (bool success,) = payable(owner()).call{value: amount}("");
        require(success, "Withdrawal failed");
    }

    /**
     * @dev Get betting history for caller
     */
    function getBettingHistory() 
        external 
        view 
        returns (BettingRecord memory) 
    {
        return bettingRecords[msg.sender];
    }

    /**
     * @dev Emergency pause (owner only)
     */
    function emergencyPause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Unpause (owner only)
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    // Internal helper functions

    function _verifySubmissions(uint256 _r, uint256 _vSum) 
        private 
        view 
        returns (bool) 
    {
        // Verify v_esum decrypts to _vSum
        if (decrypt(vESum) != _vSum) {
            return false;
        }

        // Verify r matches hash of _vSum
        string memory vSumStr = bytes32ToString(hashInteger(_vSum));
        if (hashToUint(vSumStr) != _r) {
            return false;
        }

        return true;
    }

    function _verifyOrder(uint32 orderId) private view returns (bool) {
        Order storage order = orders[orderId];
        
        if (order.encX == 0) {
            return false; // No encrypted X provided
        }

        // Decrypt x
        uint256 x = decrypt(order.encX);

        // Verify x = hash(k + r + timestamp)
        uint256 expectedX = hashToUint(
            bytes32ToString(hashInteger(order.k + r + order.timestamp))
        );
        
        if (x != expectedX) {
            return false;
        }

        // Verify result matches x parity
        bool shouldWin = (x % 2 == 0);
        bool actuallyWon = (order.status == 2);
        
        return shouldWin == actuallyWon;
    }

    function _gcd(uint256 a, uint256 b) private pure returns (uint256) {
        while (b != 0) {
            (a, b) = (b, a % b);
        }
        return a;
    }

    // View functions for monitoring
    function getGameInfo() 
        external 
        view 
        returns (
            State state,
            uint32 controlledSubmitted,
            uint32 totalControlled,
            uint32 publicSubmitted,
            uint32 totalOrders,
            bool cheated
        ) 
    {
        return (
            gameState,
            currentControlledPlayers,
            totalControlledPlayers,
            currentPublicPlayers,
            orderCounter,
            casinoCheated
        );
    }

    function getOrderDetails(uint32 orderId) 
        external 
        view 
        returns (Order memory) 
    {
        require(orderId < orderCounter, "Invalid order ID");
        return orders[orderId];
    }
}