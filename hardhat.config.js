require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  // hardhat-gas-reporter v1, the version hardhat-toolbox@5 pins.
  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
    // No CoinMarketCap key, so no live ETH price. Gas units are the honest
    // metric anyway — a dollar figure is just a snapshot of one day's gas.
    noColors: true,
    outputFile: "results/gas-report.txt",
  },
};
