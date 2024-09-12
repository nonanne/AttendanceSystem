const HelloWorld = artifacts.require("HelloWorld");

module.exports = async function (deployer, network, accounts) {
    console.log("Deploying HelloWorld contract...");
    await deployer.deploy(HelloWorld)
        .then(() => {
            console.log("HelloWorld has been deployed successfully!");
        })
        .catch(error => {
            console.error("Failed to deploy HelloWorld contract:", error);
        });
};
