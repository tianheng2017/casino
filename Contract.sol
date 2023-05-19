// SPDX-License-Identifier:MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

library ModExp {
    // 计算模幂
    function modExp(uint base, uint exponent, uint modulus) internal pure returns (uint result) {
        require(modulus != 0, "Modulus cannot be 0");
        result = 1;
        base = base % modulus;

        while (exponent > 0) {
            if (exponent % 2 == 1) {
                result = (result * base) % modulus;
            }
            exponent = exponent >> 1;
            base = (base * base) % modulus;
        }
    }

    // 计算模逆元
    function modInverse(uint a, uint m) internal pure returns(uint) {
        (int g, int x,) = extendedGcd(int(a), int(m));
        require(g == 1, "Modular inverse does not exist");
        return uint(x) % m;
    }

    // 采用迭代方式扩展的欧几里得算法
    function extendedGcd(int a, int b) internal pure returns(int, int, int) {
        int x = 0;
        int y = 1;
        int u = 1;
        int v = 0;
        
        while (a != 0) {
            int q = b / a;
            int r = b % a;
            int m = x - u * q;
            int n = y - v * q;
            b = a;
            a = r;
            x = u;
            y = v;
            u = m;
            v = n;
        }
        
        return (b, x, y);
    }
}

// 同态加密
contract Paillier {
    using ModExp for uint;

    // 以下参数虽然全部public了，但是部分值在未揭示前都是零值
    uint public p;
    uint public q;
    uint public g;

    uint public n;
    uint public nSquared;

    uint public lambda;
    uint public mu;

    constructor(uint _n) {
        // n = p * q，其中p和q都是大素数
        require(_n > 0, "n must be greater than 0");
        n = _n;
        g = _n + 1;
        nSquared = _n * _n;
    }

    function generateR() public view returns (uint) {
        uint gen = getRandomNumber();
        uint temp = gcd(gen, nSquared);

        if (temp != 1) return 1;
        return gen;
    }

    function getRandomNumber() public view returns (uint) {
        return uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 1;
    }

    function encrypt(uint message) public view returns (uint) {
        require(message < n, "Message must be smaller than n");

        uint random = generateR();
        uint temp1 = g.modExp(message, nSquared);
        uint temp2 = random.modExp(n, nSquared);

        return (temp1 * temp2) % nSquared;
    }

    function decrypt(uint ciphertext) public view returns (uint) {
        uint temp = ciphertext.modExp(lambda, nSquared);
        return (L(temp) * mu) % n;
    }

    function L(uint x) private view returns (uint) {
        return (x - 1) / n;
    }

    function lcm(uint a, uint b) private pure returns (uint) {
        return (a * b) / gcd(a, b);
    }

    function gcd(uint a, uint b) private pure returns (uint) {
        while (b != 0) {
            (a, b) = (b, a % b);
        }
        return a;
    }

    function addHomomorphically(uint enc_a, uint enc_b) public view returns (uint) {
        return (enc_a * enc_b) % nSquared;
    }

    function hashInteger(uint256 input_integer) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(input_integer));
    }

    function hashToUint(string memory inputString) public view returns (uint) {
        bytes32 hash = sha256(bytes(inputString));
        uint hashAsUint = uint(hash);
        return hashAsUint % n;
    }

    function bytes32ToString(bytes32 _bytes32) public pure returns (string memory) {
        uint8 i = 0;
        while(i < 32 && _bytes32[i] != 0) {
            i++;
        }
        bytes memory bytesArray = new bytes(i);
        for(i = 0; i < 32 && _bytes32[i] != 0; i++) {
            bytesArray[i] = _bytes32[i];
        }
        return string(bytesArray);
    }

}

// 继承于Paillier合约、ReentrancyGuard合约
contract Contract is Paillier, ReentrancyGuard {
    // 游戏状态枚举：0未开始，1进行中，2已揭示
    enum State {
        NotStarted,
        InProgress,
        Revealed
    }

    // 订单结构体
    struct Order {
        // 玩家地址
        address player;
        // 明文k
        uint k;
        // 投注金额
        uint amount;
        // 是否已结算
        bool isSettled;
        // 是否中奖：0未开奖 1未中奖 2已中奖
        uint8 status;
        // 密文x
        uint encX;
        // 投注时间
        uint timestamp;
        // 订单是否获得过赔偿：0否 1是
        bool isCompensated;
    }

    // 投注记录结构体
    struct Bet {
        uint[] ks;
        uint[] amounts;
    }

    // 合约所有者
    address public owner;

    // 投注金额1先令，相当于0.01个eth
    uint public constant BET_AMOUNT = 1 ether;

    // 要求赌场存入的最小资金
    uint public constant MIN_AMOUNT = 20 ether;

    // 揭示截止期限
    uint public constant REPORT_DEADLINE = 2 hours;

    // 未揭示前为密文r，揭示后为明文
    uint public r;

    // 当前游戏状态
    State public state;

    // 官方控制的玩家映射
    mapping(address => bool) public controlPlayer;

    // 官方控制的玩家总量
    uint public t;

    // RNG官方玩家参与数量
    uint public t_now;

    // RNG公众玩家参与数量
    uint public p_now;
    
    // 全局订单号
    uint public orderId;
    
    // 订单映射
    mapping (uint => Order) public orders;
    
    // 投注记录映射
    mapping(address => Bet) private bettingRecords;

    // 中奖记录映射
    mapping(address => uint) public winningRecords;

    // 揭示截止时间
    uint public revealDeadline;

    // 全部RNG玩家同态加法密文，v_esum = add( add(enc(v1) + enc(v2)) + ... + enc(vn) )
    uint public v_esum;

    // RNG玩家提交值映射
    mapping(address => uint) public rngEnc;

    // 赌场是否作弊
    bool public casino_cheat;

    // 修饰器，只能被合约所有人调用
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // 构造函数
    // 传入n（n = p * q）和 官方RNG玩家名单
    constructor (uint n, address[] memory _controlAddress) Paillier(n) payable {
        // 设置合约所有人为赌场
        owner = msg.sender;

        // 赌场必须存入被要求的最小资金
        require(msg.value >= MIN_AMOUNT, "Deposited funds cannot be lower than the threshold");

        // 根据题意，t = n / 2 + 1，也就是说t至少为2
        require(_controlAddress.length >= 2, "At least two players are being held by Schweizerland");

        // 登记被官方控制的玩家
        for (uint i = 0; i < _controlAddress.length; i++) {
            controlPlayer[_controlAddress[i]] = true;
            // 官方控制玩家人数 + 1
            t++;
        }
    }

    // RNG提交事件
    event eventPush(address indexed user, uint indexed enc, uint indexed v_esum);
    // 投注事件
    event eventBet(uint indexed orderId, address indexed player, uint indexed kr_esum, uint timestamp);
    // 中奖事件
    event eventLottery(uint indexed orderId, address indexed player, bool indexed result);
    // RNG完成事件
    event eventRngSuccess(uint indexed t_now, uint indexed t, uint indexed v_esum);
    // 赌场揭示事件
    event eventReveal(uint indexed r, uint indexed p, uint indexed q, uint v_sum);
    // 奖励领取事件
    event eventClaimReward(address indexed user, uint indexed amount);

    // 提交enc
    // 参数为：密文v
    function pushEnc(uint enc) external nonReentrant {
        // 要求每个人只能参与一次
        require(rngEnc[msg.sender] == 0, "Cannot participate repeatedly");
        // 要求官方玩家尚未全部参与
        require(t_now < t, "Requires Authority Players Not All Participated");
        // 要求 enc 范围为 [0, n^2)，n = p * q
        require(enc < n ** 2 && enc > 0, "The range of enc should be from 0 (inclusive) to n^2 (exclusive)");

        // 判断提交人是否在官方名单中
        bool isControlPlayer = controlPlayer[msg.sender];

        if (p_now == 0) { // 第一个提交的人必须是赌场玩家
            require(msg.sender == owner, "Casino RNG players must be the first to submit");
            p_now++;
        } else if (t_now == t - 1) { // 最后一个提交的人必须是官方玩家
            require(isControlPlayer, "Last Man Standing only accepts participation from official players");
            t_now++;
        } else { // 第2 到 t-1 位
            if (isControlPlayer == false) { // 如果是公众玩家
                // 公众玩家数量p_now最大只能为t-2，达到后不再接受公众玩家提交
                require(p_now <= t - 2, "no longer accepting public participation");
                p_now++;
            } else {
                t_now++;
            }
        }
        
        // 记录提交的enc
        rngEnc[msg.sender] = enc;

        // 计算同态加法
        if (v_esum == 0) {
            // 第一人只赋值
            v_esum = enc;
        } else {
            // 从第二人开始累加
            v_esum = addHomomorphically(v_esum, enc);
        }

        // RNG玩家参与激励，奖励合约当前余额的0.1%
        uint reward = address(this).balance / 1000;
        (bool success,) = payable(msg.sender).call{value: reward}("");
        require(success, "Failed to send");

        // 如果官方玩家已经全部参与，则播报已完成RNG，RNG阶段结束
        if (t_now == t) {
            emit eventRngSuccess(t_now, t, v_esum);
        } else {
            // 发起提交事件
            emit eventPush(msg.sender, enc, v_esum);
        }
    }

    // 赌场设置enc(r)
    // 参数为：密文r
    function setR(uint encR) external onlyOwner {
        // 要求游戏开始前设置
        require(state == State.NotStarted, "game must not be started");

        r = encR;

        // 设置完就开启游戏，以便让公众参与投注
        state = State.InProgress;
    }

    // 玩家投注
    // 参数为：明文k
    function bet(uint k) external payable nonReentrant {
        // 要求游戏状态：进行中
        require(state == State.InProgress, "game must be started");
        // 限制投注金额1先令，也就是0.01eth
        require(msg.value == BET_AMOUNT, "The betting amount is incorrect");
        // 要求合约当前余额 >= 0.04 ETH * num，如果 num 达到阈值，赌场必须增加更多的存款以继续运营，全局订单号 = 投注次数
        // 这样做的目的是，保证赌场有足够大的赔偿能力去覆盖所有的投注人
        require(address(this).balance > 0.04 ether * orderId, "Casinos must increase deposits");

        // 投注时间
        uint timestamp = block.timestamp;

        // 储存订单
        orders[orderId] = Order({
            player: msg.sender,
            k: k,
            amount: msg.value,
            isSettled: false,
            status: 0,
            encX: 0,
            timestamp: timestamp,
            isCompensated: false
        });

        // 储存投注信息，主要是提供给用户查询自己的全部投注记录
        bettingRecords[msg.sender].amounts.push(msg.value);
        bettingRecords[msg.sender].ks.push(k);

        // 将明文k加密，然后和已经是密文的k进行同态加法，算出的结果kr_esum通过事件发送给赌场
        uint kr_esum = addHomomorphically(encrypt(k), r);

        // 发出投注事件
        emit eventBet(orderId, msg.sender, kr_esum, timestamp);

        // 全局订单号自增
        orderId++;
    }

    // 赌场上传中奖结果
    // 参数为：orderId、密文x、中奖结果（1未中奖，2已中奖）
    function uploadResult(uint id, uint _encX, uint8 _status) external onlyOwner {
        // 要求游戏状态：进行中
        require(state == State.InProgress, "game must be started");
        // 要求订单是存在的
        require(orders[id].amount > 0, "order does not exist");
        // 要求订单未结算
        require(orders[id].isSettled == false, "Order must not be settled");
        // 要求状态为未中奖/已中奖
        require(_status == 1 || _status == 2, "Incorrect winning status");

        // 查找到订单
        Order storage order = orders[id];

        // 设置中奖结果、结算状态、密文x
        order.status = _status;
        order.isSettled = true;
        order.encX = _encX;

        // 如果中奖
        if (_status == 2) {
            // 记录中奖金额
            winningRecords[msg.sender] = order.amount * 2;
        }

        // 发出中奖事件
        emit eventLottery(id, order.player, _status == 2);
    }

    // 玩家领取奖励
    // 使用nonReentrant修饰器防止重入攻击
    function claimReward() external nonReentrant {
        // 要求游戏状态：进行中
        require(state == State.InProgress, "game must be started");
        // 要求有奖励金额
        require(winningRecords[msg.sender] > 0, "There is no winning amount to claim");

        // 先清零金额
        winningRecords[msg.sender] = 0;

        // 再发送奖励
        (bool success,) = payable(msg.sender).call{value: winningRecords[msg.sender]}("");
        require(success, "Failed to send");

        // 发出奖励领取事件
        emit eventClaimReward(msg.sender, winningRecords[msg.sender]);
    }

    // 赌场揭示
    // 参数为：明文p q r 和 rng玩家提交值的明文和
    function reveal(uint _r, uint _p, uint _q, uint _v_sum) external onlyOwner {
        // 要求游戏状态：进行中
        require(state == State.InProgress, "The game is not in progress");
        require(_r > 0, "r must be greater than 0");
        require(_p > 0, "p must be greater than 0");
        require(_q > 0, "q must be greater than 0");
        require(_v_sum > 0, "_v_sum must be greater than 0");

        // 验证 v_esum
        // 验证 r
        if (
            _v_sum != decrypt(v_esum) || 
            decrypt(r) != hashToUint(bytes32ToString(hashInteger(_v_sum)))
        ) {
            // 说明赌场作弊了，但揭示的时候不要回滚状态，标记即可
            casino_cheat = true;
        }

        // 揭示r、p、q
        r = _r;
        p = _p;
        q = _q;

        // 设置游戏状态：已揭示
        state = State.Revealed;

        // 设置揭示截止期限2小时
        revealDeadline = block.timestamp + REPORT_DEADLINE;

        // 发出揭示事件
        emit eventReveal(_r, _p, _q, _v_sum);
    }

    // 验证
    function verify() public returns(bool) {
        // 要求游戏状态：已揭示
        require(state == State.Revealed, "The game is not in revealed");
        // 要求在固定的时间内申请
        require(block.timestamp < revealDeadline, "revealDeadline has passed");
        // 要求订单量大于0
        require(orderId > 0, "no betting order");

        // 验证全部投注记录的x
        for (uint i = 0; i < orderId; i++) {
            // 当前order
            Order storage order = orders[i];

            // 解密encX得到明文x
            uint x = decrypt(order.encX);

            // 计算hash_to_int(hash(k + r + timestamp))，结果与x进行对比，证明x的有效性
            if (x != hashToUint(bytes32ToString(hashInteger(order.k + r + order.timestamp)))) {
                // 任何验算不通过都代表赌场作弊
                casino_cheat = true;
                break;
            }

            // 确认x有效后，再检查x的奇偶性，是否与投注记录的奇偶性一致
            if (!((x % 2 == 0 && order.status == 2) || (x % 2 != 0 && order.status == 1))) {
                // 任何验算不通过都代表赌场作弊
                casino_cheat = true;
                break;
            }
        }

        // 返回赌场是否作弊
        return casino_cheat;
    }

    // 玩家报告赌场欺诈
    // 如果赌场确实存在欺诈，智能合约将向所有受损失的玩家双倍赔偿，但需要玩家自己领取
    function report() external nonReentrant returns(bool) {
        // 要求游戏状态：已揭示
        require(state == State.Revealed, "Must be in revealed state");
        // 要求在固定的时间内申请
        require(block.timestamp < revealDeadline, "revealDeadline has passed");

        // 未作弊的状态下才会验证
        // 任何对结果有质疑的人，都可以要求智能合约进行核实
        if (casino_cheat == false) {
            verify();
        }

        // 赌场是否作弊
        return casino_cheat;
    }

    // 玩家领取欺诈赔偿
    // 使用nonReentrant防止重入攻击
    function claimCompensation() external nonReentrant {
        // 要求游戏状态：已揭示
        require(state == State.Revealed, "Must be in revealed state");
        // 要求赌场确实作弊了
        require(casino_cheat, "casino not cheating");
        // 要求总订单量大于0
        require(orderId > 0, "no betting order");
        // 要求在固定的时间内领取，过期作废
        require(block.timestamp < revealDeadline, "revealDeadline has passed");

        // 初始投注次数
        uint myBettingCount;

        // 统计总投注次数
        for (uint i = 0; i < orderId; i++) {
            // 获取引用
            Order storage order = orders[i];

            // 不是自己的订单 或 已经赔偿过了，不再处理
            if (order.player != msg.sender || order.isCompensated) continue;

            // 把订单标记为已赔偿
            order.isCompensated = true;

            // 投注次数增加
            myBettingCount++;
        }

        // 要求总投注次数大于0
        require(myBettingCount > 0, "You have not participated in betting");

        // 领取赔偿 = 投注次数 * 0.01 * 2
        (bool success,) = payable(msg.sender).call{value: myBettingCount * BET_AMOUNT * 2}("");
        require(success, "Failed to send");
    }

    // 赌场提取资金
    function ownerWithdraw() external onlyOwner {
        // 要求游戏状态：已揭示
        require(state == State.Revealed, "Must be in a revealed state");
        // 必须超过揭示截至时间
        require(block.timestamp > revealDeadline, "The disclosure deadline has expired");
        // 必须没有欺诈报告
        require(!casino_cheat, "Reports of fraud");

        // 赌场提取合约资金
        uint amount = address(this).balance;
        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success, "Failed to send");
    }

    // 玩家查询自己的投注记录
    function getBettingList() external view returns(Bet memory){
        Bet memory list = bettingRecords[msg.sender];
        return list;
    }
}