const mintNFT = artifacts.require("mintNFT");

module.exports = function (deployer) {
  deployer.deploy(mintNFT);
};
