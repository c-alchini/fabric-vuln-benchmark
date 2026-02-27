package chaincode

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

var totalCapacity uint64 // V: Global variable

type FabricVulnBenchmark struct {
	contractapi.Contract

	ownerCounter int // V: Field Declaration
}

func (sc *FabricVulnBenchmark) InitContract(ctx contractapi.TransactionContextInterface) error {
	totalCapacity = 500
	sc.ownerCounter = 1
	return nil
}

type Owner struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Age            uint64 `json:"age"`
	DocumentNumber string `json:"documentNumber"`
}

type Asset struct {
	AssetType    string `json:"assetType"`
	ID           string `json:"id"`
	Description  string `json:"description"`
	Amount       int32  `json:"amount"`
	Owner        string `json:"owner"`
	CreationTime string `json:"creationTime"`
}

// V: Non-determinism caused by the use of pointers and timestamp
func (sc *FabricVulnBenchmark) CreateAsset(ctx contractapi.TransactionContextInterface, assetID, description, assetType, ownerID string) error {
	stub := ctx.GetStub()

	assetKey, err := stub.CreateCompositeKey("asset", []string{assetID})
	if err != nil {
		return errors.New("unable to create composite key")
	}

	// V: Unhandled error
	existing, err := stub.GetState(assetKey)

	if existing != nil {
		return fmt.Errorf("cannot create world state pair with key %s. Already exists", assetID)
	}

	ownerBytes, err := stub.GetState(ownerID)
	if err != nil {
		return errors.New("unable to interact with world state")
	}
	if ownerBytes == nil {
		return errors.New("owner does not exist")
	}

	var owner Owner
	err = json.Unmarshal(ownerBytes, &owner)
	if err != nil {
		return errors.New("unable to unmarshal")
	}

	var asset Asset
	asset.AssetType = assetType
	asset.Description = description
	asset.ID = assetID
	asset.Amount = 1
	asset.Owner = fmt.Sprintf("%p", &owner)                          // V: Pointer.
	asset.CreationTime = time.Now().Format("Jan _2 15:04:05.000000") // V: Timestamp.

	assetBytes, err := json.Marshal(asset)
	if err != nil {
		return errors.New("unable to marshal asset")
	}

	err = stub.PutState(assetKey, []byte(assetBytes))
	if err != nil {
		return errors.New("unable to interact with world state")
	}

	return nil
}

// V: Privacy leakage from private data in arguments, branch condition and returned payload
func (sc *FabricVulnBenchmark) CreateOwner(ctx contractapi.TransactionContextInterface, name, documentNumber string) (string, error) {
	stub := ctx.GetStub()

	transientMap, err := stub.GetTransient()
	if err != nil {
		return "", errors.New("unable to get transient data")
	}

	age, err := strconv.ParseUint(string(transientMap["ownerAge"]), 10, 64)
	if err != nil {
		return "", errors.New("unable to parse string to uint")
	}

	if age < 18 { // V: Privacy leakage: private data in branch statement
		return "", fmt.Errorf("owner (%s, %s) must be at least 18 years old", name, documentNumber)
	}

	var ownerPublic Owner
	ownerPublic.ID = sc.ownerCounter
	sc.ownerCounter = sc.ownerCounter + 1

	ownerPublicBytes, err := json.Marshal(ownerPublic)
	if err != nil {
		return "", errors.New("unable to marshal asset")
	}

	err = stub.PutState(strconv.Itoa(ownerPublic.ID), ownerPublicBytes)
	if err != nil {
		return "", errors.New("unable to interact with world state")
	}

	var ownerPrivate Owner
	ownerPrivate.Age = age
	ownerPrivate.Name = name
	ownerPrivate.DocumentNumber = documentNumber

	ownerPrivateBytes, err := json.Marshal(ownerPrivate)
	if err != nil {
		return "", errors.New("unable to marshal asset")
	}
	err = stub.PutPrivateData("collectionID", strconv.Itoa(ownerPublic.ID), ownerPrivateBytes)
	if err != nil {
		return "", errors.New("unable to store private data")
	}

	// V: Privacy leakage in returned payload
	return fmt.Sprintf("Owner %s (%s) created successfully.", name, documentNumber), nil
}

// V: Non Determinism caused by concurrency (Go Routines), Math and Conversion overflow
func (sc *FabricVulnBenchmark) UpdateAssetAmount(ctx contractapi.TransactionContextInterface, assetID, amountsJSON string) error {
	stub := ctx.GetStub()

	var amounts []string
	if err := json.Unmarshal([]byte(amountsJSON), &amounts); err != nil {
		return err
	}

	assetKey, err := stub.CreateCompositeKey("asset", []string{assetID})
	if err != nil {
		return errors.New("unable to create composite key")
	}

	assetBytes, err := stub.GetState(assetKey)
	if err != nil {
		return errors.New("unable to interact with world state")
	}
	if assetBytes == nil {
		return fmt.Errorf("cannot update world state pair with key %s. Does not exist", assetID)
	}

	var asset Asset
	err = json.Unmarshal(assetBytes, &asset)
	if err != nil {
		return errors.New("unable to unmarshal asset")
	}

	var wg sync.WaitGroup
	for _, valueStr := range amounts {
		wg.Add(1)
		go func(incrementStr string) { // V: Concurrency
			defer wg.Done()
			value, _ := strconv.ParseInt(incrementStr, 10, 64) // V: Unhandled error leading to unsafe arithmetic

			res := asset.Amount + int32(value)           // V: Math and Conversion overflow
			if res <= int32(totalCapacity) && res >= 0 { // V: Conversion overflow
				asset.Amount = res
			}
		}(valueStr)
	}
	wg.Wait()

	updatedAssetBytes, err := json.Marshal(asset)
	if err != nil {
		return errors.New("unable to marshal asset")
	}

	err = stub.PutState(assetKey, updatedAssetBytes)
	if err != nil {
		return errors.New("unable to interact with world state")
	}

	return nil
}

// V: ReadAfterWrite
func (sc *FabricVulnBenchmark) UpdateAssetDescription(ctx contractapi.TransactionContextInterface, assetID, description string) (*Asset, error) {
	stub := ctx.GetStub()

	assetKey, err := stub.CreateCompositeKey("asset", []string{assetID})
	if err != nil {
		return nil, errors.New("unable to create composite key")
	}

	assetBytes, err := stub.GetState(assetID)
	if err != nil {
		return nil, errors.New("unable to interact with world state")
	}

	if assetBytes == nil {
		return nil, fmt.Errorf("cannot update world state pair with key %s. Does not exist", assetID)
	}

	var asset Asset
	err = json.Unmarshal(assetBytes, &asset)
	if err != nil {
		return nil, errors.New("unable to unmarshal asset")
	}

	asset.Description = description

	updatedAssetBytes, err := json.Marshal(asset)
	if err != nil {
		return nil, errors.New("unable to marshal asset")
	}

	err = stub.PutState(assetKey, updatedAssetBytes)
	if err != nil {
		return nil, errors.New("unable to interact with world state")
	}

	// V: ReadAfterWrite
	assetBytes, err = stub.GetState(assetKey)
	if err != nil {
		return nil, errors.New("unable to interact with world state")
	}

	err = json.Unmarshal(assetBytes, &asset)
	if err != nil {
		return nil, errors.New("unable to unmarshal asset")
	}

	return &asset, nil
}

func (sc *FabricVulnBenchmark) ReadAsset(ctx contractapi.TransactionContextInterface, assetID string) (*Asset, error) {
	stub := ctx.GetStub()

	assetKey, err := stub.CreateCompositeKey("asset", []string{assetID})
	if err != nil {
		return nil, errors.New("unable to create composite key")
	}

	assetBytes, err := stub.GetState(assetKey)
	if err != nil {
		return nil, errors.New("unable to interact with world state")
	}
	if assetBytes == nil {
		return nil, fmt.Errorf("cannot read world state pair with key %s. Does not exist", assetKey)
	}

	var asset Asset
	err = json.Unmarshal(assetBytes, &asset)
	if err != nil {
		return nil, errors.New("unable to unmarshal asset")
	}

	return &asset, nil
}

// V: ReadAfterWrite - Interprocedural
func (sc *FabricVulnBenchmark) UpdateAssetDescriptionInterprocedural(ctx contractapi.TransactionContextInterface, assetID, description string) (*Asset, error) {
	asset, err := sc.ReadAsset(ctx, assetID)
	if err != nil {
		return nil, err
	}

	asset.Description = description

	err = sc.writeAsset(ctx, assetID, asset)
	if err != nil {
		return nil, err
	}

	// V: ReadAfterWrite
	return sc.ReadAsset(ctx, assetID)
}

// V: Range over map.
func (sc *FabricVulnBenchmark) ReadAllAssets(ctx contractapi.TransactionContextInterface) ([]Asset, error) {
	stub := ctx.GetStub()

	iterator, err := stub.GetStateByPartialCompositeKey("asset", []string{})
	if err != nil {
		return nil, errors.New("unable to interact with world state")
	}
	defer iterator.Close()

	var assetsMap = make(map[string]Asset)
	for iterator.HasNext() {
		queryResponse, err := iterator.Next()
		if err != nil {
			return nil, errors.New("unable to get next element")
		}

		_, cKeyParts, err := stub.SplitCompositeKey(queryResponse.GetKey())
		if err != nil {
			return nil, errors.New("unable to split key")
		}

		var asset Asset
		err = json.Unmarshal(queryResponse.GetValue(), &asset)
		if err != nil {
			return nil, errors.New("unable to unmarshal")
		}

		// cKeyParts[0] is the assetKey
		assetsMap[cKeyParts[0]] = asset
	}

	var assets = make([]Asset, 0, 100)
	// V: Range over map.
	for _, asset := range assetsMap {
		assets = append(assets, asset)
	}

	return assets, nil
}

func (sc *FabricVulnBenchmark) ChangeTotalCapacity(valueStr string) error {
	value, err := strconv.ParseUint(valueStr, 10, 64)
	if err != nil {
		return errors.New("unable to parse string to uint")
	}

	totalCapacity = value

	return nil
}

// V: cross-channel invocation - simulation
func (sc *FabricVulnBenchmark) TransferAnotherAsset(ctx contractapi.TransactionContextInterface, ownerID, channel string) error {
	stub := ctx.GetStub()

	response := stub.InvokeChaincode("TransferChaincode", toChaincodeArgs("TransferAnotherAsset", ownerID), channel)
	if response.GetStatus() != shim.OK {
		return errors.New("unable to invoke another chaincode")
	}

	return nil
}

// V: Phantom Read
func (sc *FabricVulnBenchmark) UpdateAssetsByType(ctx contractapi.TransactionContextInterface, assetType string) error {
	stub := ctx.GetStub()

	queryString := fmt.Sprintf(`{"selector":{"assetType":"%s"}}`, assetType)

	resultsIterator, err := stub.GetQueryResult(queryString)
	if err != nil {
		return err
	}
	defer resultsIterator.Close()

	for resultsIterator.HasNext() {
		queryResult, err := resultsIterator.Next()
		if err != nil {
			return err
		}
		var asset Asset
		err = json.Unmarshal(queryResult.GetValue(), &asset)
		if err != nil {
			return err
		}

		asset.Amount += 1

		updatedAssetBytes, err := json.Marshal(asset)
		if err != nil {
			return errors.New("unable to marshal asset")
		}

		err = stub.PutState(queryResult.GetKey(), updatedAssetBytes)
		if err != nil {
			return errors.New("unable to interact with world state")
		}
	}

	return nil
}

// V: Unhandled Error
func (sc *FabricVulnBenchmark) UnhandledError(ctx contractapi.TransactionContextInterface, assetID string) {
	sc.ReadAsset(ctx, "AssetID")
}

func (sc *FabricVulnBenchmark) writeAsset(ctx contractapi.TransactionContextInterface, assetID string, asset *Asset) error {
	stub := ctx.GetStub()

	updatedAssetBytes, err := json.Marshal(asset)
	if err != nil {
		return errors.New("unable to marshal asset")
	}

	assetKey, err := stub.CreateCompositeKey("asset", []string{assetID})
	if err != nil {
		return errors.New("unable to create composite key")
	}

	err = stub.PutState(assetKey, updatedAssetBytes)
	if err != nil {
		return errors.New("unable to interact with world state")
	}

	return nil
}

// toChaincodeArgs receives dynamic number of strings as parameters.
// It returns array byte of chaincode args.
func toChaincodeArgs(args ...string) [][]byte {
	bargs := make([][]byte, len(args))
	for i, arg := range args {
		bargs[i] = []byte(arg)
	}

	return bargs
}
