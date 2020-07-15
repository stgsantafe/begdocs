package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/stgsantafe/begdocs/codigo_ejemplo/qr"
	"io/ioutil"
	"math/big"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("ERROR comando requiere un parametro\n")
		fmt.Printf("USO: qrsign (generar_claves, generar_cupon, prueba_cupon <qr>)\n")
		os.Exit(-1)
	}

	switch os.Args[1] {
	case "generar_cupon":
		genQrVoucher()
		break
	case "prueba_cupon":
		if len(os.Args) < 3 {
			fmt.Printf("ERROR comando requiere 2 parametros\n")
			fmt.Printf("USO: qrsign (generar_claves, generar_cupon, prueba_cupon <qr>)\n")
			os.Exit(-1)
		}
		testQr(os.Args[2])
		break
	case "generar_claves":
		genKeys()
		break
	}
}

func genKeys() {
	reader := rand.Reader
	pkey, err := ecdsa.GenerateKey(elliptic.P256(), reader)
	if err != nil {
		fmt.Printf("ERROR generar_claves :%s\n", err)
		os.Exit(-1)
	}
	publicKey := pkey.PublicKey

	savePEMKey("clave_privada_test.pem", pkey)
	savePublicPEMKey("clave_publica_test.pem", &publicKey)
	fmt.Println("claves creadas!")
}

func loadKeys() (privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) {
	pkeyBytes, err := ioutil.ReadFile("clave_privada_test.pem")
	checkError(err)
	pubBytes, err := ioutil.ReadFile("clave_publica_test.pem")
	checkError(err)

	block, _ := pem.Decode(pkeyBytes)
	x509Encoded := block.Bytes
	privateKey, err = x509.ParseECPrivateKey(x509Encoded)
	checkError(err)

	blockPub, _ := pem.Decode(pubBytes)
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey = genericPublicKey.(*ecdsa.PublicKey)
	return
}

func savePEMKey(fileName string, key *ecdsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	pkeyBytes, err := x509.MarshalECPrivateKey(key)
	checkError(err)
	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkeyBytes,
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey *ecdsa.PublicKey) {
	asn1Bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}

func genQrVoucher() {

	qrVoucher := &qr.QRVoucher{
		EmpresaId:     1,
		TipoVoucher:   2,
		TipoBeneficio: 4,
		Fecha:         &qr.Date{Day: 11, Month: 10, Year: 2020},
		Documento:     28333121,
		Nombre:        "MAIDANA, JULIO ANDRES",
		DesdeHasta:    "Santa Fe/Rosario",
		Recorrido:     11,
		VoucherId:     123123,
	}

	bodyVoucher, err := proto.Marshal(qrVoucher)
	if err != nil {
		panic(err)
	}

	secMessage := &qr.SecureMessage{}
	hAndBody := &qr.HeaderAndBody{
		Header: &qr.Header{
			EncryptionScheme: qr.EncScheme_NONE,
			SignatureScheme:  qr.SigScheme_ECDSA_P256_SHA256,
			MessageKind:      qr.MessageKind_QRVoucherKind,
		},
		Body: bodyVoucher,
	}
	dataHeadBody, err := proto.Marshal(hAndBody)
	if err != nil {
		panic(err)
	}

	// do sign
	pkey, _ := loadKeys()
	hash := sha256.Sum256(dataHeadBody)
	r, s, err := ecdsa.Sign(rand.Reader, pkey, hash[:])
	if err != nil {
		panic(err)
	}

	curveBits := pkey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}
	// We serialize the outpus (r and s) into big-endian byte arrays and pad
	// them with zeros on the left to make sure the sizes work out. Both arrays
	// must be keyBytes long, and the output must be 2*keyBytes long.
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	secMessage.Signature = append(rBytesPadded, sBytesPadded...)
	secMessage.HeaderAndBody = dataHeadBody

	dataFinal, err := proto.Marshal(secMessage)
	checkError(err)
	final := base64.StdEncoding.Strict().EncodeToString(dataFinal)
	fmt.Printf("CUPON:%s\n", final)

}

func testQr(qrString string) {

	qrBytes, err := base64.StdEncoding.DecodeString(qrString)
	checkError(err)
	secMessage := &qr.SecureMessage{}
	err = proto.Unmarshal(qrBytes, secMessage)
	checkError(err)

	headAndBody := &qr.HeaderAndBody{}
	err = proto.Unmarshal(secMessage.HeaderAndBody, headAndBody)
	checkError(err)

	// verify
	_, pubkey := loadKeys()
	hash := sha256.Sum256(secMessage.HeaderAndBody)

	if len(secMessage.Signature) != 2*32 {
		checkError(fmt.Errorf("ERROR firma digital con tamaño erroneo"))
	}

	r := big.NewInt(0).SetBytes(secMessage.Signature[:32])
	s := big.NewInt(0).SetBytes(secMessage.Signature[32:])

	verified := ecdsa.Verify(pubkey, hash[:], r, s)
	if verified {
		fmt.Println("CLAVE VERIFICADA")
	} else {
		fmt.Println("CLAVE NO VERIFICADA")
		os.Exit(0)
	}
	// voucher
	if headAndBody.Header.MessageKind == qr.MessageKind_QRVoucherKind {
		qrVoucher := &qr.QRVoucher{}
		err = proto.Unmarshal(headAndBody.Body, qrVoucher)
		checkError(err)
		fmt.Printf("Coupon Id:%d\n", qrVoucher.VoucherId)
		fmt.Printf("Empresa Id:%d\n", qrVoucher.EmpresaId)
		fmt.Printf("Desde / Hasta: %s\n", qrVoucher.DesdeHasta)
		fmt.Printf("Fecha Viaje: %d/%d/%d\n", qrVoucher.Fecha.Day, qrVoucher.Fecha.Month, qrVoucher.Fecha.Year)
		fmt.Printf("Beneficiario Documento:%d\n", qrVoucher.Documento)
		fmt.Printf("Beneficiario Nombre:%s\n", qrVoucher.Nombre)
	} else {
		fmt.Println("NO ES UN CUPON")
	}

}
