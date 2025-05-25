package main

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

type AttestationRecord struct {
	ReportHash string `json:"reportHash"`
	Signature  string `json:"signature"` // Assuming signature is base64 encoded string
	Timestamp  string `json:"timestamp"`
	AgentID    string `json:"agentID"`    // Optional: Identifier for the TEE agent
}

// InitLedger adds initial data to the ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	records := []AttestationRecord{
		{
			ReportHash: "sampleHash1",
			Signature:  "sampleSig1",
			Timestamp:  "2024-01-01T12:00:00Z",
			AgentID:    "agent1",
		},
		{
			ReportHash: "sampleHash2",
			Signature:  "sampleSig2",
			Timestamp:  "2024-01-02T13:00:00Z",
			AgentID:    "agent2",
		},
	}

	for i, record := range records {
		recordJSON, err := json.Marshal(record)
		if err != nil {
			return err
		}

		key := fmt.Sprintf("ATT%03d", i)
		err = ctx.GetStub().PutState(key, recordJSON)
		if err != nil {
			return err
		}
	}

	return nil
}


// StoreAttestation adds a new record to the ledger
func (s *SmartContract) StoreAttestation(ctx contractapi.TransactionContextInterface, id string, reportHash string, signature string, timestamp string, agentID string) error {
	exists, err := s.AttestationExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the attestation %s already exists", id)
	}

	record := AttestationRecord{
		ReportHash: reportHash,
		Signature:  signature,
		Timestamp:  timestamp,
		AgentID:    agentID,
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, recordJSON)
}

// QueryAttestation retrieves a record from the ledger
func (s *SmartContract) QueryAttestation(ctx contractapi.TransactionContextInterface, id string) (*AttestationRecord, error) {
	recordJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if recordJSON == nil {
		return nil, fmt.Errorf("the attestation %s does not exist", id)
	}

	var record AttestationRecord
	err = json.Unmarshal(recordJSON, &record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// AttestationExists checks if a record exists
func (s *SmartContract) AttestationExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	recordJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return recordJSON != nil, nil
}

// QueryAllAttestations returns all attestation records found in world state
func (s *SmartContract) QueryAllAttestations(ctx contractapi.TransactionContextInterface) ([]*AttestationRecord, error) {
    resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
    if err != nil {
        return nil, err
    }
    defer resultsIterator.Close()

    var records []*AttestationRecord
    for resultsIterator.HasNext() {
        queryResponse, err := resultsIterator.Next()
        if err != nil {
            return nil, err
        }

        var record AttestationRecord
        err = json.Unmarshal(queryResponse.Value, &record)
        if err != nil {
            return nil, err
        }
        records = append(records, &record)
    }

    return records, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		fmt.Printf("Error creating attestation chaincode: %v", err)
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting attestation chaincode: %v", err)
	}
}
