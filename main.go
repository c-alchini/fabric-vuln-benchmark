package main

import (
	"github.com/c-alchini/fabric-vuln-benchmark/chaincode"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

func main() {
	cc, err := contractapi.NewChaincode(&chaincode.FabricVulnBenchmark{})

	if err != nil {
		panic(err.Error())
	}

	if err := cc.Start(); err != nil {
		panic(err.Error())
	}
}
