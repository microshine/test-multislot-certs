## Installing

```
git clone https://github.com/microshine/test-multislot-certs.git
cd test-multislot-certs
npm install
```

## Start

```
npm run start
```

## SoftHSM

### Get list of slots
```
softhsm2-util --show-slots
```

### Create new slot

```
softhsm2-util --init-token --so-pin <SO-PIN> --pin <PIN> --slot <INDEX> --label <NAME>
```