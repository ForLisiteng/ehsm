package ehsm

import (
	"encoding/base64"
	"testing"
)

func Test_EC_SignVerify(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Error(err)
	}
	keyspec := [5]string{"EH_EC_P224", "EH_EC_P256", "EH_EC_P256K", "EH_EC_P384", "EH_EC_P521"}
	for _, keyspec := range keyspec {
		keyid, err := client.CreateKey(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
		if err != nil {
			t.Error(err)
		}
		signature, err := client.Sign(keyid, base64.StdEncoding.EncodeToString([]byte("test")), "EH_RAW", "EH_PAD_NONE", "EH_SHA_256")
		if err != nil {
			t.Error(err)
		}
		result, err := client.Verify(keyid, base64.StdEncoding.EncodeToString([]byte("test")), signature, "EH_RAW", "EH_PAD_NONE", "EH_SHA_256")
		if result != true {
			t.Error(err)
		}
	}
}

func Test_RSA_SignVerify(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Error(err)
	}
	keyspec := [3]string{"EH_RSA_3072", "EH_RSA_4096", "EH_RSA_2048"}
	for _, keyspec := range keyspec {
		keyid, err := client.CreateKey(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
		if err != nil {
			t.Error(err)
		}
		signature, err := client.Sign(keyid, base64.StdEncoding.EncodeToString([]byte("test")), "EH_RAW", "EH_RSA_PKCS1", "EH_SHA_256")
		if err != nil {
			t.Error(err)
		}
		result, err := client.Verify(keyid, base64.StdEncoding.EncodeToString([]byte("test")), signature, "EH_RAW", "EH_RSA_PKCS1", "EH_SHA_256")
		if result != true {
			t.Error(err)
		}
	}
}

func Test_SM2_SignVerify(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Error(err)
	}
	keyid, err := client.CreateKey("EH_SM2", "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
	if err != nil {
		t.Error(err)
	}
	signature, err := client.Sign(keyid, base64.StdEncoding.EncodeToString([]byte("test")), "EH_RAW", "EH_PAD_NONE", "EH_SM3")
	if err != nil {
		t.Error(err)
	}
	result, err := client.Verify(keyid, base64.StdEncoding.EncodeToString([]byte("test")), signature, "EH_RAW", "EH_PAD_NONE", "EH_SM3")
	if result != true {
		t.Error(err)
	}
}
