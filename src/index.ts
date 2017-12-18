import * as asn1js from "asn1js";
import { WebCrypto } from "node-webcrypto-p11";
const pkijs = require("pkijs");
const { Extension } = pkijs;

const alg = {
    name: "ECDSA",
    hash: {
        name: "SHA-256",
    },
    namedCurve: "P-256",
};

interface X500Name {
    [type: string]: string;
}

interface ICertInfo {
    serialNumber?: Uint8Array;
    issuer: X500Name;
    subject: X500Name;
    notBefore?: Date;
    notAfter?: Date;
    publicKey: CryptoKey;
    keyUsage?: string[];
}

async function GenerateKeys(crypto: Crypto) {
    return crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
}

async function CreateCertificate(crypto: WebCrypto, params: ICertInfo, caKey: CryptoKey) {
    pkijs.setEngine('Crypto', crypto, new pkijs.CryptoEngine({ name: "Crypto", crypto, subtle: crypto.subtle }));
    const certificate = new pkijs.Certificate();

    certificate.version = 2;

    //#region Serial number
    const serialNumber = params.serialNumber || crypto.getRandomValues(new Uint8Array(10));
    certificate.serialNumber = new asn1js.Integer();
    certificate.serialNumber.valueBlock.valueHex = (serialNumber as Uint8Array).buffer;
    //#endregion

    //#region Subject name
    for (const type in params.subject) {
        const name = new pkijs.AttributeTypeAndValue({
            type,
            value: new asn1js.PrintableString({ value: params.subject[type] }),
        });

        certificate.subject.typesAndValues.push(name);
    }
    //#endregion

    //#region Issuer name
    for (const type in params.issuer) {
        const name = new pkijs.AttributeTypeAndValue({
            type,
            value: new asn1js.PrintableString({ value: params.issuer[type] }),
        });

        certificate.issuer.typesAndValues.push(name);
    }
    //#endregion

    //#region Valid period
    certificate.notBefore.value = params.notBefore || new Date(); // current date
    if (!params.notAfter) {
        const notAfter = new Date(certificate.notBefore.value.getTime());
        notAfter.setFullYear(notAfter.getFullYear() + 1);
        certificate.notAfter.value = notAfter;
    } else {
        certificate.notAfter.value = params.notAfter;
    }
    //#endregion

    //#region Extensions

    certificate.extensions = []; // Extensions are not a part of certificate by default, it's an optional array
    //#region Key usage
    const bitArray = new ArrayBuffer(1);
    const bitView = new Uint8Array(bitArray);
    bitView[0] |= 0x80; // digitalSignature
    const keyUsage = new asn1js.BitString({ valueHex: bitArray });

    certificate.extensions.push(
        new Extension({
            extnID: '2.5.29.15',
            critical: false,
            extnValue: keyUsage.toBER(false),
            parsedValue: keyUsage, // Parsed value for well-known extensions
        }),
    );
    //#endregion

    //#endregion

    await certificate.subjectPublicKeyInfo.importKey(params.publicKey);
    await certificate.sign(caKey, "SHA-256");

    const ber = certificate.toSchema(false).toBER(false);
    const cryptoCert = await crypto.certStorage.importCert("x509", ber, alg, ["verify"]);
    return cryptoCert;
}

async function Test1() {

    const slot1 = new WebCrypto({
        library: "/usr/local/lib/softhsm/libsofthsm2.so",
        name: "SoftHSMv2",
        slot: 0,
        pin: "12345",
        readWrite: true,
    });
    const slot2 = new WebCrypto({
        library: "/usr/local/lib/softhsm/libsofthsm2.so",
        name: "SoftHSMv2",
        slot: 1,
        pin: "12345",
        readWrite: true,
    });
    //#region Create CA
    const caKeys = await GenerateKeys(slot1);
    const caName: X500Name = {
        "2.5.4.3": "CA #1",
    };
    const caCert = await CreateCertificate(
        slot1,
        {
            subject: caName,
            issuer: caName,
            publicKey: caKeys.publicKey,
        },
        caKeys.privateKey,
    );
    console.log("CA cert: OK");
    //#endregion

    //#region Create User certs
    const userKeys1 = await GenerateKeys(slot1);
    const userKeys2 = await GenerateKeys(slot2);
    const subjectName: X500Name = {
        "2.5.4.3": "Ivanov I.I.",
    };

    const cert1 = await CreateCertificate(
        slot1,
        {
            serialNumber: new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1]),
            subject: subjectName,
            issuer: caName,
            publicKey: userKeys1.publicKey,
        },
        caKeys.privateKey,
    );
    console.log("User cert #1: OK");
    const cert2 = await CreateCertificate(
        slot1,
        {
            serialNumber: new Uint8Array([0, 0, 0, 0, 0, 0, 0, 2]),
            subject: subjectName,
            issuer: caName,
            publicKey: userKeys1.publicKey,
        },
        caKeys.privateKey,
    );
    console.log("User cert #2: OK");

    const jwk = await slot2.subtle.exportKey("jwk", userKeys2.publicKey);
    const cert3PubKey = await slot2.subtle.importKey("jwk", jwk, alg, true, ["verify"]);
    const cert3 = await CreateCertificate(
        slot1,
        {
            serialNumber: new Buffer([0, 0, 0, 0, 0, 0, 0, 2]),
            subject: subjectName,
            issuer: caName,
            publicKey: cert3PubKey,
        },
        caKeys.privateKey,
    );
    const cert3Raw = await slot1.certStorage.exportCert("raw", cert3);
    const cert3Slot2 = await slot1.certStorage.importCert("x509", cert3Raw, alg, ["verify"]);
    console.log("User cert #3: OK");
    //#endregion

    //#region Push objects to slot
    slot1.keyStorage.setItem(caKeys.privateKey);
    slot1.certStorage.setItem(caCert);
    slot1.keyStorage.setItem(userKeys1.privateKey);
    slot1.certStorage.setItem(cert1);
    slot1.certStorage.setItem(cert2);

    slot2.keyStorage.setItem(userKeys2.privateKey);
    slot2.certStorage.setItem(cert3Slot2);
    //#endregion
}

async function main() {
    await Test1();
    console.log("Success");
}

main()
    .catch((err) => {
        console.error(err);
    })