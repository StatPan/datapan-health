package schemas

import "testing"

const expectedHealthOperationPlanProbeV1SchemaSHA256 = "c5c7ee3ae3fee24c2a94f065fa723fc8727c5b16c45c397e2c7d88de64e1b416"

func TestHealthOperationPlanProbeV1SchemaPinAndValidation(t *testing.T) {
	if got := HealthOperationPlanProbeV1SchemaSHA256(); got != expectedHealthOperationPlanProbeV1SchemaSHA256 {
		t.Fatalf("operation plan receipt schema digest = %s", got)
	}
	valid := []byte(`{"schema_version":"datapan.health-operation-plan-probe.v1","attempt_id":"817c7c1d-f844-4b79-bdad-891a273c1a4e","cli":{"version":"v0.1.41","binary_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"registry":{"dataset_id":"StatPan/datapan-registry","registry_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","distribution":"huggingface_dataset","distribution_dataset_revision":"cccccccccccccccccccccccccccccccccccccccc","registry_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","manifest_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","operation_manifest_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","provider_index_sha256":"1111111111111111111111111111111111111111111111111111111111111111","plan_schema_sha256":"2222222222222222222222222222222222222222222222222222222222222222","index_sha256":"3333333333333333333333333333333333333333333333333333333333333333","shard_sha256":"4444444444444444444444444444444444444444444444444444444444444444","source_identity_set_sha256":"5555555555555555555555555555555555555555555555555555555555555555"},"operation":{"operation_id":"6666666666666666666666666666666666666666666666666666666666666666","source_id":"data_go_kr","provider":"data.go.kr","adapter_id":"data-go-kr","protocol":"REST"},"execution":{"request_started":false,"request_budget":0,"timeout_ms":1000,"duration_ms":1},"observation":{"response_observed":false,"outcome":"blocked","reason_code":"credential_binding_unavailable","assertion_kind":"json_contract","assertion_status":"not_run"},"redaction":{"credential_values_removed":true,"credential_references_removed":true,"credential_env_names_removed":true,"query_values_removed":true,"request_body_removed":true,"response_body_removed":true,"response_rows_removed":true,"endpoint_details_removed":true,"quota_details_removed":true}}`)
	if err := ValidateHealthOperationPlanProbeV1(valid); err != nil {
		t.Fatalf("valid blocked receipt rejected: %v", err)
	}
	unknown := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"provider_url":"https://example.invalid/?key=secret"}`)...)
	if err := ValidateHealthOperationPlanProbeV1(unknown); err == nil {
		t.Fatal("receipt schema accepted an endpoint field")
	}
}
