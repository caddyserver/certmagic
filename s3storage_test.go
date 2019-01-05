package certmagic

import (
	"testing"
	"time"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"bytes"
	"io/ioutil"
	"errors"
	"github.com/aws/aws-sdk-go/aws"
)

type mockedS3 struct {
	s3iface.S3API
	objectKeys map[string][]byte
}

var (
	MockStore = &S3Storage{}
	errPutObject = errors.New("could not put object")
	tstamp = time.Now()
)

func init() {

	mocks3 := mockedS3{
		objectKeys: make(map[string][]byte),
	}
	mocks3.objectKeys["existingKey"] = []byte("test")

	MockStore = NewS3Storage("test-bucket", "us-east-1")
	MockStore.svc = mocks3
}

func (m mockedS3) GetObject(input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	//rc := ioutil.NewReadCloser(bytes.NewReader([]byte("blobl")), nil)
	for k, v := range m.objectKeys {
		if *input.Key == k {
			rc := ioutil.NopCloser(bytes.NewReader(v))
			return &s3.GetObjectOutput{
				Body:rc,
				LastModified: aws.Time(tstamp),
				ContentLength: aws.Int64(int64(len(v))),
			}, nil
		}
	}
	return nil, awserr.New(s3.ErrCodeNoSuchKey, *input.Key, nil)
}

func (m mockedS3) PutObject(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	if len(*input.Key) > 9 {
		bod, _ := ioutil.ReadAll(input.Body)
		if len(bod) > 0 {
			m.objectKeys[*input.Key] = bod
			return &s3.PutObjectOutput{}, nil
		}
	}
	return nil, errPutObject
}

func (m mockedS3) DeleteObject(input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	for k, _ := range m.objectKeys {
		if *input.Key == k {
			delete(m.objectKeys, *input.Key)
			return &s3.DeleteObjectOutput{}, nil
		}
	}
	return nil, awserr.New(s3.ErrCodeNoSuchKey, *input.Key, nil)
}


var testStore *S3Storage

func init() {
	testStore = NewS3Storage("test-bucket", "us-east-1")
}

func TestS3Storage_Exists(t *testing.T) {
	cases := []struct{
		input string
		expected bool

	}{
		{"existingKey", true},
		{ "testKey", false},
	}
	for _, c := range cases {
		got := MockStore.Exists(c.input)
		if got != c.expected {
			t.Errorf("\nexpected: %+v     \ngot: %+v", c.expected, got)
		}
	}
}

func TestS3Storage_Store(t *testing.T) {
	cases := []struct{
		inputKey string
		inputValue []byte
		expected error

	}{
		{"a key", []byte("Test"), nil},
		{ "", nil, errPutObject},
		{ "test", nil, errPutObject},
		{ "", []byte("test"), errPutObject},
	}
	for _, c := range cases {
		got := MockStore.Store(c.inputKey, c.inputValue)
		if got != c.expected {
			t.Errorf("\nexpected: %+v     \ngot: %+v", c.expected, got)
		}
	}
}

func TestS3Storage_Load(t *testing.T) {
	cases := []struct{
		input string
		expected []byte
	} {
		{"existingKey", []byte("test")},
		{"nonExistentKey", nil},
	}

	if err := MockStore.Store("existingKey", []byte("test")); err != nil {
		t.Error(err)
	}

	for _, c := range cases {
		got, _ := MockStore.Load(c.input)
		if string(got) != string(c.expected) {
			t.Errorf("\ninput: %s\nexpected: %+v     \ngot: %+v", c.input, string(c.expected), string(got))
		}
	}
}

func TestS3Storage_Delete(t *testing.T) {
	input := "existingKey"
	got := MockStore.Delete("existingKey")
	if got != nil {
		t.Errorf("\ninput: %s\nexpected: %+v\n     got: %+v", input, nil, got)
	}
	input = "nonExistantKey"
	got = MockStore.Delete(input)
	if got == nil {
		t.Errorf("\ninput: %s\nexpected: %+v\n     got: %+v", input, awserr.New(s3.ErrCodeNoSuchKey, MockStore.Filename(input), nil) , got)
	}
}

func TestS3Storage_Stat(t *testing.T) {
	cases := []struct{
		input string
		expected KeyInfo
	} {
		{"existingKey", KeyInfo{Key: "existingKey", Size: 4, Modified: tstamp, IsTerminal:true}},
		{"nonExistentKey", KeyInfo{}},
	}
	for _, c := range cases {
		got, _ := MockStore.Stat(c.input)
		if got != c.expected {
			t.Errorf("\ninput: %s\nexpected: %+v\n     got: %+v", c.input, c.expected, got)
		}
	}
}


func TestS3Storage_LockUnlock(t *testing.T) {
	lock1 := "testLock1"
	got := MockStore.Lock(lock1)
	if got != nil {
		t.Errorf("\ninput: %s\nexpected: %+v\n     got: %+v", lock1, nil, got)
	}

	got = MockStore.Unlock(lock1)
	if got != nil {
		t.Errorf("\ninput: %s\nexpected: %+v\n     got: %+v", lock1, nil, got)
	}

	got = MockStore.Lock(lock1)
	if got != nil {
		t.Errorf("\ninput: %s\nexpected: %+v\n     got: %+v", lock1, nil, got)
	}

	//this should fail since we already have a lock on lock1

}


func TestS3Storage_String(t *testing.T) {
	expected := "S3Storage:certmagic"
	if testStore.String() != expected {
		t.Errorf("Expected: %s, go %s", expected, testStore.String())
	}
}


func TestS3Storage_lockDir(t *testing.T) {
	expected := "certmagic/locks"
	got := testStore.lockDir()
	if got != expected {
		t.Errorf("Expected: %s, got: %s", expected, got)
	}
}

func TestS3Storage_fileLockIsStale(t *testing.T) {
	info := KeyInfo{
		Key: "key",
		Modified: time.Now().Add(-time.Hour*999),
	}
	expected := true
	got := testStore.fileLockIsStale(info)
	if !got {
		t.Errorf("Expected: %t, got: %t", expected, got)
	}
}
