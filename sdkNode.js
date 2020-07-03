/**
 * Copyright 2017 IBM All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an 'AS IS' BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
'use strict';
var log4js = require('log4js');
var logger = log4js.getLogger('SampleWebApp');
var express = require('express');
var session = require('express-session');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var http = require('http');
var util = require('util');
var app = express();
var cors = require('cors');
const Config = require('./config.json');

require('./config.js');
var hfc = require('fabric-client');

var helper = require('./app/helper.js');
var createChannel = require('./app/create-channel.js');
var join = require('./app/join-channel.js');
var updateAnchorPeers = require('./app/update-anchor-peers.js');
var install = require('./app/install-chaincode.js');
var instantiate = require('./app/instantiate-chaincode.js');
var invoke = require('./app/invoke-transaction.js');
var query = require('./app/query.js');
var host = process.env.HOST || hfc.getConfigSetting('host');
var port = process.env.PORT || hfc.getConfigSetting('portSdkNode');

var chaincode = require('./app/chaincode.js');
var parseChainCode = require('./app/parse-chaincode.js');
const chaincodeHandler = require('./app/chaincode/handler');
const dbHelper = require('./app/db-handler');
dbHelper.initialize();
///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// SET CONFIGURATONS ////////////////////////////
///////////////////////////////////////////////////////////////////////////////
app.options('*', cors());
app.use(cors());
//support parsing of application/json type post data
app.use(bodyParser.json());
//support parsing of application/x-www-form-urlencoded post data
app.use(bodyParser.urlencoded({
    extended: false
}));

// // set secret variable
// app.set('secret', 'thisismysecret');
// app.use(expressJWT({
//     secret: 'thisismysecret'
// }).unless({
//     path: ['/users']
// }));
// app.use(bearerToken());

app.use(function(req, res, next) {
    logger.debug(' ------>>>>>> new request for %s',req.originalUrl);
    let email = req.get('email');
    logger.info(email);
    logger.info("%o",req.body);
    return next();
});

///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// START SERVER /////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
var server = http.createServer(app).listen(port,'localhost',function() {});
logger.info('****************** SERVER STARTED ************************');
logger.info('***************  http://%s:%s  ******************',host,port);
server.timeout = 240000;

function getErrorMessage(field) {
    var response = {
        success: false,
        message: field + ' field is missing or Invalid in the request'
    };
    return response;
}


///////////////////////////////////////////////////////////////////////////////
///////////////////////// REST ENDPOINTS START HERE ///////////////////////////
///////////////////////////////////////////////////////////////////////////////

// Create Channel
app.post('/channels', async function (req, res) {
    logger.info('<<<<<<<<<<<<<<<<< C R E A T E  C H A N N E L >>>>>>>>>>>>>>>>>');
    logger.debug('End point : /channels');
    var channelName = req.body.channelName;
    var channelConfigPath = req.body.channelConfigPath;
    channelConfigPath = '../artifacts/channel/' + channelName + '.tx'
    logger.debug('Channel name : ' + channelName);
    logger.debug('channelConfigPath : ' + channelConfigPath); //../artifacts/channel/mychannel.tx
    if (!channelName) {
        res.json(getErrorMessage('\'channelName\''));
        return;
    }
    if (!channelConfigPath) {
        res.json(getErrorMessage('\'channelConfigPath\''));
        return;
    }
    let message = await createChannel.createChannel(channelName, channelConfigPath, req.username, req.orgname);
    res.send(message);
});
// Join Channel
app.post('/channels/:channelName/peers', async function (req, res) {
    logger.info('<<<<<<<<<<<<<<<<< J O I N  C H A N N E L >>>>>>>>>>>>>>>>>');
    var channelName = req.params.channelName;
    var peers = req.body.peers;
    logger.debug('channelName : ' + channelName);
    logger.debug('peers : ' + peers);
    logger.debug('username :' + req.username);
    logger.debug('orgname:' + req.orgname);

    if (!channelName) {
        res.json(getErrorMessage('\'channelName\''));
        return;
    }
    if (!peers || peers.length == 0) {
        res.json(getErrorMessage('\'peers\''));
        return;
    }

    let message = await join.joinChannel(channelName, peers, req.username, req.orgname);
    res.send(message);
});
// Update anchor peers
app.post('/channels/:channelName/anchorpeers', async function (req, res) {
    logger.debug('==================== UPDATE ANCHOR PEERS ==================');
    var channelName = req.params.channelName;
    var configUpdatePath = req.body.configUpdatePath;
    logger.debug('Channel name : ' + channelName);
    logger.debug('configUpdatePath : ' + configUpdatePath);
    if (!channelName) {
        res.json(getErrorMessage('\'channelName\''));
        return;
    }
    if (!configUpdatePath) {
        res.json(getErrorMessage('\'configUpdatePath\''));
        return;
    }

    let message = await updateAnchorPeers.updateAnchorPeers(channelName, configUpdatePath, req.username, req.orgname);
    res.send(message);
});
// Install chaincode on target peers
app.post('/chaincodes', async function (req, res) {
    logger.debug('==================== INSTALL CHAINCODE ==================');
    var peers = req.body.peers;
    var chaincodeName = req.body.chaincodeName;
    var chaincodePath = req.body.chaincodePath;
    var chaincodeVersion = req.body.chaincodeVersion;
    var chaincodeType = req.body.chaincodeType;
    logger.debug('peers : ' + peers); // target peers list
    logger.debug('chaincodeName : ' + chaincodeName);
    logger.debug('chaincodePath  : ' + chaincodePath);
    logger.debug('chaincodeVersion  : ' + chaincodeVersion);
    logger.debug('chaincodeType  : ' + chaincodeType);
    if (!peers || peers.length == 0) {
        res.json(getErrorMessage('\'peers\''));
        return;
    }
    if (!chaincodeName) {
        res.json(getErrorMessage('\'chaincodeName\''));
        return;
    }
    if (!chaincodePath) {
        res.json(getErrorMessage('\'chaincodePath\''));
        return;
    }
    if (!chaincodeVersion) {
        res.json(getErrorMessage('\'chaincodeVersion\''));
        return;
    }
    if (!chaincodeType) {
        res.json(getErrorMessage('\'chaincodeType\''));
        return;
    }
    let message = await install.installChaincode(peers, chaincodeName, chaincodePath, chaincodeVersion, chaincodeType, req.username, req.orgname)
    res.send(message);
});
// Upgrade chaincode version on target peers
app.post('/upgrade', async function (req, res) {
    logger.debug('==================== UPGRADE CHAINCODE ==================');
    var peers = req.body.peers;
    var chaincodeName = req.body.chaincodeName;
    var chaincodePath = req.body.chaincodePath;
    var chaincodeVersion = req.body.chaincodeVersion;
    var chaincodeType = req.body.chaincodeType;
    var channelName = 'mychannel'
    logger.debug('peers : ' + peers); // target peers list
    logger.debug('chaincodeName : ' + chaincodeName);
    logger.debug('chaincodePath  : ' + chaincodePath);
    logger.debug('chaincodeVersion  : ' + chaincodeVersion);
    logger.debug('chaincodeType  : ' + chaincodeType);
    if (!peers || peers.length == 0) {
        res.json(getErrorMessage('\'peers\''));
        return;
    }
    if (!chaincodeName) {
        res.json(getErrorMessage('\'chaincodeName\''));
        return;
    }
    if (!chaincodePath) {
        res.json(getErrorMessage('\'chaincodePath\''));
        return;
    }
    if (!chaincodeVersion) {
        res.json(getErrorMessage('\'chaincodeVersion\''));
        return;
    }
    if (!chaincodeType) {
        res.json(getErrorMessage('\'chaincodeType\''));
        return;
    }
    let message = await upgrade.upgradeChainCode(peers, chaincodeName, chaincodePath, chaincodeVersion, chaincodeType, req.username, req.orgname, channelName)
    res.send(message);
});
// Instantiate chaincode on target peers
app.post('/channels/:channelName/chaincodes', async function (req, res) {
    logger.debug('==================== INSTANTIATE CHAINCODE ==================');
    var peers = req.body.peers;
    var chaincodeName = req.body.chaincodeName;
    var chaincodeVersion = req.body.chaincodeVersion;
    var channelName = req.params.channelName;
    var chaincodeType = req.body.chaincodeType;
    var fcn = req.body.fcn;
    var args = req.body.args;
    logger.debug('peers  : ' + peers);
    logger.debug('channelName  : ' + channelName);
    logger.debug('chaincodeName : ' + chaincodeName);
    logger.debug('chaincodeVersion  : ' + chaincodeVersion);
    logger.debug('chaincodeType  : ' + chaincodeType);
    logger.debug('fcn  : ' + fcn);
    logger.debug('args  : ' + args);
    if (!chaincodeName) {
        res.json(getErrorMessage('\'chaincodeName\''));
        return;
    }
    if (!chaincodeVersion) {
        res.json(getErrorMessage('\'chaincodeVersion\''));
        return;
    }
    if (!channelName) {
        res.json(getErrorMessage('\'channelName\''));
        return;
    }
    if (!chaincodeType) {
        res.json(getErrorMessage('\'chaincodeType\''));
        return;
    }
    if (!args) {
        res.json(getErrorMessage('\'args\''));
        return;
    }

    let message = await instantiate.instantiateChaincode(peers, channelName, chaincodeName, chaincodeVersion, chaincodeType, fcn, args, req.username, req.orgname);
    res.send(message);
});
// Invoke transaction on chaincode on target peers
app.post('/channels/:channelName/chaincodes/:chaincodeName', async function (req, res) {
    logger.debug('==================== INVOKE ON CHAINCODE ==================');
    var peers = req.body.peers;
    var chaincodeName = req.params.chaincodeName;
    var channelName = req.params.channelName;
    var fcn = req.body.fcn;
    var args = req.body.args;
    var username = req.get('email')
    logger.debug('channelName  : ' + channelName);
    logger.debug('chaincodeName : ' + chaincodeName);
    logger.debug('fcn  : ' + fcn);
    logger.debug('args  : ' + args);
    if (!chaincodeName) {
        res.json(getErrorMessage('\'chaincodeName\''));
        return;
    }
    if (!channelName) {
        res.json(getErrorMessage('\'channelName\''));
        return;
    }
    if (!fcn) {
        res.json(getErrorMessage('\'fcn\''));
        return;
    }
    if (!args) {
        res.json(getErrorMessage('\'args\''));
        return;
    }
    await createChannel.checkChannelNetworkConfig(channelName)
    let message = await invoke.invokeChaincode(peers, channelName, chaincodeName, fcn, args, username, Config.orgs.org1.name);
    res.send(message);
});
// Query on chaincode on target peers
app.get('/channels/:channelName/chaincodes/:chaincodeName', async function (req, res) {
    logger.debug('==================== QUERY BY CHAINCODE ==================');
    var channelName = req.params.channelName;
    var chaincodeName = req.params.chaincodeName;
    let args = req.query.args;
    let fcn = req.query.fcn;
    let peer = req.query.peer;
    let email = req.get('email');
    logger.debug('channelName : ' + channelName);
    logger.debug('chaincodeName : ' + chaincodeName);
    logger.debug('fcn : ' + fcn);
    logger.debug('args : ' + args);

    if (!chaincodeName) {
        res.json(getErrorMessage('\'chaincodeName\''));
        return;
    }
    if (!channelName) {
        res.json(getErrorMessage('\'channelName\''));
        return;
    }
    if (!fcn) {
        res.json(getErrorMessage('\'fcn\''));
        return;
    }
    if (!args) {
        res.json(getErrorMessage('\'args\''));
        return;
    }
    args = args.replace(/'/g, '"');
    args = JSON.parse(args);
    logger.debug(args);
    res.statusCode = 200

    peer = Config.peers.org1[0]
    // peer = "Org1";
    await createChannel.checkChannelNetworkConfig(channelName)
    try {
        let message = await query.queryChaincode(peer, channelName, chaincodeName, args, fcn, email, Config.orgs.org1.name);
        if (message.status) {
            res.json({ success: false, message: message.result });
            return
        }
        res.json({ success: true, message: message.result });
        return

    } catch (error) {
        logger.debug(error)
    }

    return
});
//  Query Get Block by BlockNumber
app.get('/channels/:channelName/blocks/:blockId', async function (req, res) {
    logger.debug('==================== GET BLOCK BY NUMBER ==================');
    let blockId = req.params.blockId;
    let peer = req.query.peer;
    logger.debug('channelName : ' + req.params.channelName);
    logger.debug('BlockID : ' + blockId);
    logger.debug('Peer : ' + peer);
    if (!blockId) {
        res.json(getErrorMessage('\'blockId\''));
        return;
    }

    let message = await query.getBlockByNumber(peer, req.params.channelName, blockId, req.username, req.orgname);
    res.send(message);
});
// Query Get Transaction by Transaction ID
app.get('/channels/:channelName/transactions/:trxnId', async function (req, res) {
    logger.debug('================ GET TRANSACTION BY TRANSACTION_ID ======================');
    logger.debug('channelName : ' + req.params.channelName);
    let trxnId = req.params.trxnId;
    let peer = req.query.peer;
    if (!trxnId) {
        res.json(getErrorMessage('\'trxnId\''));
        return;
    }

    let message = await query.getTransactionByID(peer, req.params.channelName, trxnId, req.username, req.orgname);
    res.send(message);
});
// Query Get Block by Hash
app.get('/channels/:channelName/blocks', async function (req, res) {
    logger.debug('================ GET BLOCK BY HASH ======================');
    logger.debug('channelName : ' + req.params.channelName);
    let hash = req.query.hash;
    let peer = req.query.peer;
    if (!hash) {
        res.json(getErrorMessage('\'hash\''));
        return;
    }

    let message = await query.getBlockByHash(peer, req.params.channelName, hash, req.username, Config.orgs.org1.name);
    res.send(message);
});
//Query for Channel Information
app.get('/channels/:channelName', async function (req, res) {
    logger.debug('================ GET CHANNEL INFORMATION ======================');
    logger.debug('channelName : ' + req.params.channelName);
    let peer = req.query.peer;

    let message = await query.getChainInfo(peer, req.params.channelName, req.get('email'), req.orgname);
    res.send(message);
});
//Query for Channel instantiated chaincodes
app.get('/channels/:channelName/chaincodes', async function (req, res) {
    logger.debug('================ GET INSTANTIATED CHAINCODES ======================');
    logger.debug('channelName : ' + req.params.channelName);
    let peer = req.query.peer;

    let message = await query.getInstalledChaincodes(peer, req.params.channelName, 'instantiated', req.username, req.orgname);
    res.send(message);
});
// Query to fetch all Installed/instantiated chaincodes
app.get('/chaincodes', async function (req, res) {
    var peer = req.query.peer;
    var installType = req.query.type;
    logger.debug('================ GET INSTALLED CHAINCODES ======================');

    let message = await query.getInstalledChaincodes(peer, null, 'installed', req.username, req.orgname)
    res.send(message);
});
// Query to fetch channels
app.get('/channels', async function (req, res) {
    logger.debug('================ GET CHANNELS ======================');
    logger.debug('peer: ' + req.query.peer);
    var peer = req.query.peer;
    if (!peer) {
        res.json(getErrorMessage('\'peer\''));
        return;
    }

    let message = await query.getChannels(peer, req.username, req.orgname);
    res.send(message);
});

//////

// Install chaincode on target peers
app.post('/channels/:channelName/chaincodes/:chaincodeName/deploy', async function (req, res) {
    res.statusCode = 400
    logger.debug('==================== Deploy CHAINCODE ==================');
    var email = req.get('email');
    var channelName = req.params.channelName;
    var chaincodeName = req.params.chaincodeName;
    var chainCode = req.body.chainCode
    var chaincodeType = req.body.type
    if (!email) {
        res.json(getErrorMessage('unknown user'));
        return;
    }
    if (!chaincodeType || chaincodeType != "golang") {
        res.json(getErrorMessage('invalid type'));
        return;
    }
    if (!chainCode) {
        res.json(getErrorMessage('invalid chainCode'));
        return;
    }
    if (!chaincodeName) {
        res.json(getErrorMessage('invalid chaincodeName'));
        return;
    }
    if (!channelName) {
        res.json(getErrorMessage('invalid channelName'));
        return;
    }

    var chaincodePath = null;
    var chaincodeVersion = null;
    var username = req.get('email')
    var fcn = req.body.fcn;
    var args = req.body.args;
    var basePath = __dirname + "/artifacts/src/"

    try {

        var decodedChainCode = helper.decodeFromBase64(chainCode)
        var currentUser = await dbHelper.getPersistance().getCrudService().getUser(email);
        if (!currentUser) {
            res.json(getErrorMessage('User not found'));
            return;
        }
        var userId = currentUser.id
        let cc = await chaincodeHandler.getChainCodeByName(userId, chaincodeName, chaincodeType);

        if (!cc) {
            let chainCodeId = chaincode.getUUID()
            let path = await chaincode.createDirectory(userId, chainCodeId)
            chaincodePath = chaincode.getChainPath(path)

            chaincodeVersion = channelName + "v0"
            await chaincode.createFile(basePath + chaincodePath, chaincodeName, chaincodeType, decodedChainCode)
            await chaincode.modInit(basePath + chaincodePath, chaincodeName)
            await chaincode.build(basePath + chaincodePath, chaincodeName)

            var result = await chaincodeHandler.saveChainCode(userId, chaincodeName, chaincodeType, 0, chaincodePath, chainCode);
            if (!result) {
                throw new Error("Error in creating chaincode")
            }
        } else {
            chaincodePath = cc.chain_code_path
            let newVersion = cc.chain_code_version + 1
            chaincodeVersion = channelName + "v" + newVersion
            chaincodeName = cc.chain_code_name
            chaincodeType = cc.chain_code_type
            await chaincode.createFile(basePath + chaincodePath, chaincodeName, chaincodeType, decodedChainCode)
            await chaincode.modInit(basePath + chaincodePath, chaincodeName)
            await chaincode.build(basePath + chaincodePath, chaincodeName)


            result = await chaincodeHandler.updateChainCode(userId, chaincodeName, chaincodeType, newVersion, chaincodePath, chainCode);
            if (!result) {
                throw new Error("Error in updating chaincode")
            }

        }

        logger.debug('chaincodeName : ' + chaincodeName);
        logger.debug('chaincodePath  : ' + chaincodePath);
        logger.debug('chaincodeVersion  : ' + chaincodeVersion);
        logger.debug('chaincodeType  : ' + chaincodeType);
        logger.debug('fcn  : ' + fcn);
        logger.debug('args  : ' + args);

        if (!chaincodeName) {
            res.json(getErrorMessage('\'chaincodeName\''));
            return;
        }
        if (!chaincodePath) {
            res.json(getErrorMessage('\'chaincodePath\''));
            return;
        }
        if (!chaincodeVersion) {
            res.json(getErrorMessage('\'chaincodeVersion\''));
            return;
        }
        if (!chaincodeType) {
            res.json(getErrorMessage('\'chaincodeType\''));
            return;
        }
        if (!username) {
            res.json(getErrorMessage('\'username\''));
            return;
        }

        await chaincode.modVendor(basePath + chaincodePath, chaincodeName)
        await createChannel.checkChannelNetworkConfig(channelName)

        let message = await install.installChaincode(Config.peers.org1, chaincodeName, chaincodePath, chaincodeVersion, chaincodeType, username, Config.orgs.org1.name)
        if (!message.success) {
            res.send(message);
            return
        }
        // message = await install.installChaincode(Config.peers.org2, chaincodeName, chaincodePath, chaincodeVersion, chaincodeType, username, Config.orgs.org2.name)
        // if (!message.success) {
        // 	res.send(message);
        // 	return
        // }

        if (cc && (cc.chain_code_version > -1)) {
            message = await upgrade.upgradeChainCode(Config.peers.org1, chaincodeName, chaincodePath, chaincodeVersion, chaincodeType, username, Config.orgs.org1.name, channelName)
        } else {
            message = await instantiate.instantiateChaincode(null, channelName, chaincodeName, chaincodeVersion, chaincodeType, fcn, args, username, Config.orgs.org1.name);
        }
        if (!message.success) {
            res.send(message);
            return
        }

        var placeHolders = parseChainCode.getPlaceHolders(chaincodePath, chaincodeName, chaincodeType)
        var dapp = parseChainCode.parse(decodedChainCode, chaincodeName, chaincodeType, placeHolders)
        message.dapp = dapp
        res.statusCode = 200
        res.send(message);
    } catch (error) {
        logger.error(error)
        return res.send({success: false, message: error.message})
    }
});

// View chaincode on target peers
app.get('/channels/:channelName/chaincodes/:chaincodeName/view', async function (req, res) {
    logger.debug('==================== View CHAINCODE ==================');
    var chaincodeName = req.params.chaincodeName;
    var channelName = req.params.channelName;
    var email = req.get('email');
    logger.debug('channelName  : ' + channelName);
    logger.debug('chaincodeName : ' + chaincodeName);
    if (!chaincodeName) {
        res.json(getErrorMessage('\'chaincodeName\''));
        return;
    }
    if (!channelName) {
        res.json(getErrorMessage('\'channelName\''));
        return;
    }

    let currentUser = await dbHelper.getPersistance().getCrudService().getUser(email);
    if (!currentUser) {
        res.json(getErrorMessage('User not found'));
        return;
    }

    var userId = currentUser.id
    let cc = await chaincodeHandler.getChainCodeByName(userId, chaincodeName, "golang");
    if (!cc) {
        res.json(getErrorMessage('Chaincode not found'));
        return;
    }
    let chainCodePath = cc.chain_code_path;
    let chainCodeType = cc.chain_code_type;
    let ccCoded = cc.chain_code;

    let buff = new Buffer.from(ccCoded, 'base64');
    let chainCode = buff.toString('ascii');
    let ccDecoded = helper.decodeFromBase64(chainCode)


    var placeHolders = parseChainCode.getPlaceHolders(chainCodePath, chaincodeName, chainCodeType)
    var dapp = parseChainCode.parse(ccDecoded, chaincodeName, chainCodeType, placeHolders)

    res.send({success: true, chaincodeName: chaincodeName, type: chainCodeType, chaincode: chainCode, dapp: dapp});
});


// Save chaincode
app.post('/channels/:channelName/chaincodes/:chaincodeName/save', async function (req, res) {
    res.statusCode = 400
    logger.debug('==================== Save CHAINCODE ==================');
    var email = req.get('email')
    var channelName = req.params.channelName;
    var chaincodeName = req.params.chaincodeName;
    var chainCode = req.body.chainCode
    var chaincodeType = req.body.type
    if (!email) {
        res.json(getErrorMessage('\'unknown user\''));
        return;
    }
    if (!chaincodeType || chaincodeType != "golang") {
        res.json(getErrorMessage('invalid type'));
        return;
    }
    if (!chainCode) {
        res.json(getErrorMessage('invalid chainCode'));
        return;
    }
    if (!chaincodeName) {
        res.json(getErrorMessage('invalid chaincodeName'));
        return;
    }
    if (!channelName) {
        res.json(getErrorMessage('channelName'));
        return;
    }

    var chaincodePath = null;
    var urlPath = null;
    var basePath = __dirname + "/artifacts/src/"

    try {

        var decodedChainCode = helper.decodeFromBase64(chainCode)
        var currentUser = await dbHelper.getPersistance().getCrudService().getUser(email);
        if (!currentUser) {
            res.json(getErrorMessage('User not found'));
            return;
        }
        var userId = currentUser.id
        let cc = await chaincodeHandler.getChainCodeByName(userId, chaincodeName, chaincodeType);

        if (!cc) {
            let chainCodeId = chaincode.getUUID()
            let path = await chaincode.createDirectory(userId, chainCodeId)
            chaincodePath = chaincode.getChainPath(path)
            var result = await chaincodeHandler.saveChainCode(userId, chaincodeName, chaincodeType, -1, chaincodePath);
            if (!result) {
                throw new Error("Error in creating chaincode")
            }
            await chaincode.createFile(basePath + chaincodePath, chaincodeName, chaincodeType, decodedChainCode)
            await chaincode.modInit(basePath + chaincodePath, chaincodeName)
        } else {
            chaincodePath = cc.chain_code_path
            chaincodeName = cc.chain_code_name
            chaincodeType = cc.chain_code_type
            await chaincodeHandler.updateChainCode(basePath + chaincodePath, chaincodeName, chaincodeType, decodedChainCode)
        }

        let url = await chaincode.genratePublicUrl(chaincodePath, chaincodeName, chaincodeType)
        res.statusCode = 200
        res.send({success: true, url: url});
    } catch (error) {
        logger.error(error)
        return res.send({success: false, message: error.message})
    }
});
