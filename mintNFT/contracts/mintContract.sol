// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";

contract mintContract is ERC721URIStorage, Ownable{
    using Counters for Counters.Counter;
    Counters.Counter private tokenID;

    constructor() ERC721("Luxury Items NFT", "LXI"){

    }

    function mintNFT(string memory tokenURI) public onlyOwner returns (uint256){
        tokenID.increment();
        uint256 newID = tokenID.current();

        _mint(msg.sender, newID);
        _setTokenURI(newID, tokenURI);

        return newID;
    }
}