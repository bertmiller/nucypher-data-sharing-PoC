pragma solidity ^0.5.0;

/**
 * 
 */
contract PaymentStore {
  /*
   *  Storage
   */
  address public owner;
  
  uint256 public payment_num = 100000000;
  
  mapping(address => uint256) public money_owned;
  mapping(address => bytes) public key_store;
  mapping(address => string) public ipfs_store;
  /*
   *  Modifiers
   */
  modifier onlyOwner() {
    require(owner == msg.sender, "only-owner-allowed");
    _;
  }

  /*
   * Public functions
   */
  /// @dev Contract constructor sets initial owner.
  constructor() public {
    owner = msg.sender;
  }
  
  function recordNeed() external {
    money_owned[msg.sender] = payment_num;
  }
  
  function getNuAddress(address _add) external view returns (bytes memory value) {
    return key_store[_add];
  }
  
  function setNuData(address _add, bytes calldata _value) external {
    key_store[_add] = _value;
  }
  
  function getIpfs(address _add) external view returns (string memory value) {
    return ipfs_store[_add];
  }
  
  function setIpfsData(address _add, string calldata _value) external {
    ipfs_store[_add] = _value;
  }
}
