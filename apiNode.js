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
var expressJWT = require('express-jwt');
var jwt = require('jsonwebtoken');
var bearerToken = require('express-bearer-token');
var multer = require('multer')
var cors = require('cors');
// const fs = require('fs');
const Config = require('./config.json');

require('./config.js');
var hfc = require('fabric-client');
var crypto = require('crypto');
const dbHelper = require('./app/db-handler');
const templateHandler = require('./app/templates/handler');
var helper = require('./app/helper.js');
var vo = require('./app/vo.js');
var createChannel = require('./app/create-channel.js');
var join = require('./app/join-channel.js');
var updateAnchorPeers = require('./app/update-anchor-peers.js');
var install = require('./app/install-chaincode.js');
var instantiate = require('./app/instantiate-chaincode.js');
var invoke = require('./app/invoke-transaction.js');
var upgrade = require('./app/upgrade-chaincode.js');
var query = require('./app/query.js');
var user = require('./app/user.js');
var emailService = require('./app/email.js')
var host = process.env.HOST || hfc.getConfigSetting('host');
var port = process.env.PORT || hfc.getConfigSetting('portApiNode');
var sdkPort = process.env.PORT || hfc.getConfigSetting('portSdkNode');
var swaggerUi = require('swagger-ui-express');
var swaggerDocument = require('./app/swagger.json');
const sdkConst = require('./app/common/constants').sdk.const


///========
dbHelper.initialize();
var express = require('express');
var path = require('path');
const mkdirp = require('mkdirp');
var aws = require('aws-sdk');
var multerS3 = require('multer-s3');

aws.config.update({
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || Config.aws.secretAccessKey,
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || Config.aws.accessKeyId,
    region: process.env.AWS_REGION || Config.aws.region
});

var s3 = new aws.S3();

var upload = multer({
    storage: multerS3({
        s3: s3,
        bucket: process.env.AWS_BUCKET_NAME || Config.aws.bucketName,
        acl: 'public-read',
        key: function (req, file, cb) {
            console.log(file);
            cb(null, `${Date.now().toString()}${file.originalname}`); //use Date.now() for unique file keys
        }
    })
});
var storagequotations = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = 'uploads/quotations'
        mkdirp(dir, err => cb(err, dir))
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname) //+ path.extname(file.originalname)) //Appending extension
    }
})
var uploadquotation = multer({storage: storagequotations})


///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// SET CONFIGURATONS ////////////////////////////
///////////////////////////////////////////////////////////////////////////////
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.options('*', cors());
app.use(cors());
//support parsing of application/json type post data
app.use(bodyParser.json());
//support parsing of application/x-www-form-urlencoded post data
app.use(bodyParser.urlencoded({
    extended: false
}));
var filter = function (req) {
    return true;
}
// set secret variable
app.set('secret', hfc.getConfigSetting('jwtSecret'));
app.use(expressJWT({
    secret: hfc.getConfigSetting('jwtSecret')
}).unless(filter));
app.use(bearerToken());
app.use(async function (req, res, next) {
    logger.debug(' ------>>>>>> new request for %s', req.originalUrl);
    if ((req.originalUrl.indexOf('/users') >= 0) ||
        (req.originalUrl.indexOf('/signup') >= 0) ||
        (req.originalUrl.indexOf('/signin') >= 0) ||
        (req.originalUrl.indexOf('/images') >= 0) ||
        (req.originalUrl.indexOf('/verifyemail/') >= 0) ||
        (req.originalUrl.indexOf('/contact') >= 0) ||
        (req.originalUrl.indexOf('/user/password/forgot') >= 0) ||
        (req.originalUrl.indexOf('/chaincode/parse') >= 0) ||
        (req.originalUrl.indexOf('/files') >= 0) ||
        (req.originalUrl.indexOf('/template') >= 0) ||
        (req.originalUrl.indexOf('/health') >= 0)
    ) {
        return next();
    }

    // 아래 /chaincode/parse 를 처리하는 부분 없음.

    logger.info('req.body : %o ', req.body);

    // var channelName = req.url.split('/')[2].split('?')[0];
    var api_key = req.get('api-key');
    var channelName = req.get('channel');
    logger.info("channelName : %s , api_key : %s", channelName, api_key);
    if (channelName && api_key) {

        var userKeySignin = await dbHelper.getPersistance().getCrudService().getUserKey(channelName, api_key);
        if (userKeySignin) {
            logger.info('start sdk');

            var response = http.request({
                hostname: 'localhost',
                path: req.originalUrl,
                port: sdkPort,
                headers: {
                    'content-type': 'application/json',
                    'email': userKeySignin.email
                },
                method: req.method
            }, function (response) {
                var serverData = '';
                response.on('data', function (chunk) {
                    serverData += chunk;
                });
                response.on('end', function () {
                    res.send(serverData);
                });
            }).end();

            return;

        } else {
            res.statusCode = 400
            res.send({
                success: false,
                message: 'api-Key and channel are not matched or the value is incorrect'
            });
            return;
        }
    }

    var token = req.token;
    if (token) {
        jwt.verify(token, app.get('secret'), function (err, decoded) {
            if (err) {
                res.statusCode = 400
                res.send({
                    success: false,
                    message: 'Failed to authenticate token. Make sure to include the ' +
                        'token returned from /users call in the authorization header ' +
                        ' as a Bearer token'
                });
                return;
            } else {
                // Config
                // add the decoded user name and org name to the request object
                // for the downstream code to use
                var post_data = JSON.stringify(req.body);
                if ((req.originalUrl.indexOf('/user') >= 0)){
                    req.email = decoded.email;
                    return next();
                }
                var response = http.request({
                    hostname: 'localhost',
                    path: req.originalUrl,
                    port: sdkPort,
                    headers: {
                        'content-type': 'application/json',
                        'Content-Length': post_data.length,
                        'email': decoded.email
                    },
                    method: req.method
                }, function (response) {
                    var serverData = '';
                    response.on('data', function (chunk) {
                        serverData += chunk;
                    });
                    response.on('end', function () {
                        res.send(serverData);
                    });
               });

                response.write(post_data);
                response.end();

                return;
            }
        });
    }else {
        res.statusCode = 400
        res.send({
            success: false,
            message: 'Failed to authenticate token.'
        });
        return;
    }

});

///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// START SERVER /////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
var server = http.createServer(app).listen(port, function () {
});
logger.info('****************** SERVER STARTED ************************');
logger.info('***************  http://%s:%s  ******************', host, port);

server.timeout = 240000;

function getErrorMessage(field) {
    var response = {
        success: false,
        message: field
    };
    return response;
}


///////////////////////////////////////////////////////////////////////////////
//////////////////////////// REST WEB START HERE //////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Register and enroll user
app.post('/users', async function (req, res) {
    var username = req.body.username;
    var orgName = req.body.orgName;
    var role = req.body.role;
    logger.debug('End point : /users');
    logger.debug('User name : ' + username);
    logger.debug('Org name  : ' + orgName);
    logger.debug('role  : ' + role);
    if (!username) {
        res.json(getErrorMessage('\'username\''));
        return;
    }
    if (!orgName) {
        res.json(getErrorMessage('\'orgName\''));
        return;
    }
    if (!role) {
        res.json(getErrorMessage('\'role\''));
        return;
    }
    var token = jwt.sign({
        exp: Math.floor(Date.now() / 1000) + parseInt(hfc.getConfigSetting('jwt_expiretime')),
        username: username,
        orgName: orgName
    }, app.get('secret'));
    let response = await helper.getRegisteredUser(username, orgName, true, role);
    logger.debug('-- returned from registering the username %s for organization %s', username, orgName);
    if (response && typeof response !== 'string') {
        logger.debug('Successfully registered the username %s for organization %s', username, orgName);
        response.token = token;
        res.json(response);
    } else {
        logger.debug('Failed to register the username %s for organization %s with::%s', username, orgName, response);
        res.json({ success: false, message: response });
    }

});

// controller for user sign up
app.post('/signup', async function (req, res) {
    logger.debug('================ Sign Up ======================');
    res.statusCode = 400;
    const {username, email, password} = req.body
    if (!username.trim()) {
        res.json(getErrorMessage('Invalid user name'));
        return;
    }
    var re = /\S+@\S+\.\S+/;
    if ((!email.trim()) || (!re.test(email))) {
        res.json(getErrorMessage('Invalid email address'));
        return;
    }
    var strongRegex = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})");
    if (password.length < 8 || (!strongRegex.test(password))) {
        res.json(getErrorMessage('Password length should be greater than 8 with upper and lower case letters, numbers and special chars'));
        return;
    }

    var permission = user.checkPermission(email)
    if (!permission) {
        res.json(getErrorMessage('Permission denied'));
        return;
    }

    var passwordhash = crypto.createHash('md5').update(password).digest('hex')
    var channelName = sdkConst.CHANNEL_PREFIX + crypto.randomBytes(16).toString("hex");
    var APIKey = sdkConst.APIKEY_PREFIX + crypto.randomBytes(16).toString("hex");
    let newuser = {
        email: email.trim(),
        username: username.trim(),
        passwd: passwordhash,
        channel_name: channelName,
        api_key: APIKey
    }
    let userSignup = await dbHelper.getPersistance().getCrudService().saveUser(newuser);
    if (!userSignup) {
        res.json(getErrorMessage('Email Already exists'));
        return;
    }

    var token = emailService.generateVerficationEmailToken(email);
    var verificationEmail = emailService.createVerificationEmail(email, token);
    emailService.sendEmail(verificationEmail);

    res.statusCode = 200;
    var response = "A verification link has been sent to your registered email address. Follow the instructions to complete registration"
    res.json({success: true, message: response});
    return;

});

// controller for user sign in
app.post('/signin', async function (req, res) {
    logger.debug('================ Sign IN ======================');
    res.statusCode = 400;
    const {email, password} = req.body
    var re = /\S+@\S+\.\S+/;
    if ((!email) || (!re.test(email))) {
        res.json(getErrorMessage('Invalid email address'));
        return;
    }
    var userSignin = await dbHelper.getPersistance().getCrudService().getUser(email);
    if (!userSignin) {
        res.json(getErrorMessage('Email address not registered'));
        return;
    }
    if (!userSignin.email_verified) {
        res.json(getErrorMessage('Email not verified'));
        return;
    }
    var hash = crypto.createHash('md5').update(password).digest('hex')
    if (userSignin.passwd != hash) {
        res.json(getErrorMessage('Invalid password'));
        return;
    }

    var permission = user.checkPermission(email)
    if (!permission) {
        res.json(getErrorMessage('Permission denied'));
        return;
    }

    let channelName = userSignin.channel_name

    let channelInfo = await createChannel.getChannelGenesisHash(channelName)
    let channel_genesis_hash = ""
    if (channelInfo) {
        channel_genesis_hash = channelInfo.channel_genesis_hash;
    }

    var token = jwt.sign({
        exp: Math.floor(Date.now() / 1000) + parseInt(hfc.getConfigSetting('jwt_expiretime')),
        email: email,
        orgs: ["Org1", "Org2"]
    }, app.get('secret'));

    var userVo = vo.createUserVo(userSignin, channel_genesis_hash, channelName)

    res.statusCode = 200;
    res.send({success: true, token: token, user: userVo})
});


// Writing a file from local to MongoDB
app.post('/template', async function (req, res) {

    try {
        const {name, path, imageurl, type, descr} = req.body
        let responce = await templateHandler.addTemplate(name, path, imageurl, type, descr)
        res.send({success: responce.success, message: responce.message})
    } catch (e) {
        res.statusCode = 400;
        res.send({success: false, message: "Invalid file"})
    }
});

// Get the list of templates
app.get('/template', async function (req, res) {

    try {
        let responce = await templateHandler.getTemplates()
        res.send({success: responce.success, message: responce.message})
    } catch (e) {
        res.statusCode = 400;
        res.send({success: false, message: "Invalid file"})
    }
});

// Get a template by name
app.get('/template/:id', async function (req, res) {
    // Check file exist on MongoDB

    let id = req.params.id
    res.statusCode = 200;
    if (!id) {
        res.json(getErrorMessage('\'invalid id\''));
        return;
    }
    try {
        let responce = await templateHandler.getTemplateByID(id)
        res.send({success: responce.success, message: responce.message})
    } catch (e) {
        res.statusCode = 400;
        res.send({success: false, message: "Invalid file"})
    }

});

// Get the user
app.get('/user', async function (req, res) {
    res.statusCode = 400;

    var email = req.email
    if (!email) {
        res.json(getErrorMessage('\'unauthorized\''));
        return;
    }

    let userSignin = await dbHelper.getPersistance().getCrudService().getUser(req.email);
    if (!userSignin) {
        res.json(getErrorMessage('Invalid email'));
        return;
    }
    var userVo = vo.createUserVo(userSignin)
    res.statusCode = 200;
    res.send(userVo)
});

//API verifyemail
app.get('/verifyemail/:token', async function (req, res) {
    res.statusCode = 400;
    try {
        var token = req.params.token
        const {verificationEmail} = jwt.verify(token, app.get('secret'))
        if (!verificationEmail) {
            res.json(getErrorMessage('Invalid token'));
            return;
        }

        let User = await dbHelper.getPersistance().getCrudService().getUser(verificationEmail);
        if (!User) {
            res.json(getErrorMessage('User not found'));
            return;
        }
        let channelName = User.channel_name


        var role = "user"
        var org1Name = "Org1"
        response = await helper.getRegisteredUser(verificationEmail, org1Name, true, role);
        logger.debug('-- returned from registering the username %s for organization %s', verificationEmail, org1Name);

        if (response && typeof response !== 'string') {
            logger.debug('Successfully registered the username %s for organization %s', verificationEmail, org1Name);
            res.statusCode = 200;

        } else {
            logger.debug('Failed to register the username %s for organization %s with::%s', verificationEmail, org1Name, response);
            res.json({success: false, message: response});
            return;
        }

        let message = await createChannel.createCustomChannel(channelName, verificationEmail);
        message = await join.joinChannel(channelName, Config.peers.org1, verificationEmail, org1Name);

        User.email_verified = 1
        var response = await dbHelper.getPersistance().getCrudService().updateUser(User);
        if (!response) {
            res.json(getErrorMessage('User not found'));
            return;
        }

        // var org2Name = "Org2"
        // response = await helper.getRegisteredUser(email, org2Name, true, role);
        // logger.debug('-- returned from registering the username %s for organization %s', email, org2Name);

        // if (response && typeof response !== 'string') {
        // 	logger.debug('Successfully registered the username %s for organization %s', email, org2Name);
        // 	res.statusCode = 200;

        // } else {
        // 	logger.debug('Failed to register the username %s for organization %s with::%s', email, org2Name, response);
        // 	res.json({ success: false, message: response });
        // 	return;
        // }

        res.statusCode = 200;
        res.send({success: false, message: "successfully verified"})
        return


    } catch (e) {
        res.statusCode = 400;
        res.send({success: false, message: "Invalid Token"})
    }
});


// Get the user
app.put('/user', async function (req, res) {
    res.statusCode = 400;
    const {name, email} = req.body

    var re = /\S+@\S+\.\S+/;
    if ((!email) || (!re.test(email))) {
        res.json(getErrorMessage('Invalid email address'));
        return;
    }

    if (!name) {
        res.json(getErrorMessage('Invalid user name'));
        return;
    }

    let User = await dbHelper.getPersistance().getCrudService().getUser(email);
    if (!User) {
        res.json(getErrorMessage('User not found'));
        return;
    }
    User.username = name
    var response = await dbHelper.getPersistance().getCrudService().updateUser(User);
    if (!response) {
        res.json(getErrorMessage('User not found'));
        return;
    }


    var userVo = vo.createUserVo(User)
    res.statusCode = 200;
    res.send(userVo)

});

app.get("/images", (req, res) => {
    var imageUrl = req.query.imageUrl
    res.sendFile(path.join(__dirname, "./uploads/images/" + imageUrl));
});

app.get("/files", (req, res) => {
    var fileUrl = req.query.fileUrl
    var splits = fileUrl.split("/")
    var fileName = splits[splits.length - 1]
    res.statusCode = 200;
    var filePath = path.join(__dirname, "./artifacts/src/" + fileUrl)
    res.download(filePath, fileName);
});

app.post('/user/image', upload.array('image', 1), async (req, res) => {
    var email = req.email
    if (!email) {
        res.json(getErrorMessage('\'unauthorized\''));
        return;
    }

    if (req.files) {
        var ImageUrl = req.files[0].location

        let User = await dbHelper.getPersistance().getCrudService().getUser(email);
        if (!User) {
            res.json(getErrorMessage('User not found'));
            return;
        }
        User.image_url = ImageUrl
        var response = await dbHelper.getPersistance().getCrudService().updateUser(User);
        if (!response) {
            res.json(getErrorMessage('User not found'));
            return;
        }
        res.json(req.files);

    }
});

app.post('/contact', async (req, res) => {
    res.statusCode = 400;

    var firstname = req.body.firstname;
    var email = req.body.email;
    var question = req.body.question;
    if (!firstname) {
        res.json(getErrorMessage('\'firstname\''));
        return;
    }
    if (!email) {
        res.json(getErrorMessage('\'email\''));
        return;
    }
    if (!question) {
        res.json(getErrorMessage('\'question\''));
        return;
    }

    var contactEmail = emailService.createContactEmail(firstname, email, question);
    emailService.sendEmail(contactEmail);

    res.statusCode = 200;
    var response = "Successfully submitted"
    res.json({success: true, message: response});
    return;

});

app.get("/user/image", (req, res) => {
    var imageUrl = req.query.imageUrl
    res.sendFile(path.join(__dirname, "./uploads/images/" + imageUrl));
});

app.post('/user/password/forgot', async (req, res) => {
    res.statusCode = 400;

    var email = req.body.email;
    if (!email) {
        res.json(getErrorMessage('\'email\''));
        return;
    }


    let User = await dbHelper.getPersistance().getCrudService().getUser(email);
    if (!User) {
        res.json(getErrorMessage('User not found'));
        return;
    }
    User.email_verified = 0
    var response = await dbHelper.getPersistance().getCrudService().updateUser(User);
    if (!response) {
        res.json(getErrorMessage('User not found'));
        return;
    }

    var token = emailService.generateVerficationEmailToken(email);
    var forgotPasswordEmail = emailService.createForgotPassEmail(email, token);
    emailService.sendEmail(forgotPasswordEmail);

    res.statusCode = 200;
    var response = "A verification link has been sent to your registered email address. Follow the instructions to reset your password"
    res.json({success: true, message: response});
    return;

});

app.post('/user/password/change', async (req, res) => {
    res.statusCode = 400;

    var oldPassword = req.body.oldPassword;
    var newPassword = req.body.newPassword;
    var email = req.email
    if (!email) {
        res.json(getErrorMessage('\'invalid token\''));
        return;
    }

    if (!oldPassword) {
        res.json(getErrorMessage('\'oldPassword\''));
        return;
    }

    if (!newPassword) {
        res.json(getErrorMessage('\'newPassword\''));
        return;
    }

    var strongRegex = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})");
    if (newPassword.length < 8 || (!strongRegex.test(newPassword))) {
        res.json(getErrorMessage('Password length should be greater than 8 with upper and lower case letters, numbers and special chars'));
        return;
    }

    var oldPasshash = crypto.createHash('md5').update(oldPassword).digest('hex')
    var client = await dbHelper.getPersistance().getCrudService().getUser(email);
    if (!client) {
        res.json(getErrorMessage('User not found'));
        return;
    }
    if (client.passwd != oldPasshash) {
        res.json(getErrorMessage('Old Password does not match'));
        return;
    }

    var newPasshash = crypto.createHash('md5').update(newPassword).digest('hex')
    client.passwd = newPasshash
    var response = await dbHelper.getPersistance().getCrudService().updateUser(client);
    if (!response) {
        res.json(getErrorMessage('User not found'));
        return;
    }

    res.statusCode = 200;
    res.json({success: true, message: "Your password has been changed."});
    return;

});
app.post('/user/password/reset', async (req, res) => {
    res.statusCode = 400;

    var newPassword = req.body.newPassword;
    var email = req.verificationEmail
    if (!email) {
        res.json(getErrorMessage('\'invalid token\''));
        return;
    }

    if (!newPassword) {
        res.json(getErrorMessage('\'newPassword\''));
        return;
    }

    var strongRegex = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})");
    if (newPassword.length < 8 || (!strongRegex.test(newPassword))) {
        res.json(getErrorMessage('Password length should be greater than 8 with upper and lower case letters, numbers and special chars'));
        return;
    }

    let User = await dbHelper.getPersistance().getCrudService().getUser(email);
    if (!User) {
        res.json(getErrorMessage('User not found'));
        return;
    }
    var newPasshash = crypto.createHash('md5').update(newPassword).digest('hex')

    User.email_verified = 1
    User.passwd = newPasshash
    var response = await dbHelper.getPersistance().getCrudService().updateUser(User);
    if (!response) {
        res.json(getErrorMessage('User not found'));
        return;
    }

    res.statusCode = 200;
    res.json({success: true, message: "Your password has been changed."});
    return;

});

// controller for user sign up
app.post('/ondemand', uploadquotation.single('fileData'), async function (req, res) {
    logger.debug('================ On Demand ======================', req.body);
    res.statusCode = 400;
    try {
        var companyName = req.body.companyName;
        var personincharge = req.body.personincharge;
        var phoneNo = req.body.phoneNo
        var emailaddress = req.body.emailaddress
        var serviceRequest = req.body.serviceRequest
        var recaptcha = req.body.recaptcha
        logger.debug('On Demand Information:', companyName, personincharge, phoneNo, emailaddress, serviceRequest);
        if (!recaptcha.trim()) {
            res.json(getErrorMessage('Invalid recaptcha'));
            return;
        }
        if (!personincharge.trim()) {
            res.json(getErrorMessage('Invalid Person In Charge'));
            return;
        }
        if (!phoneNo.trim()) {
            res.json(getErrorMessage('Invalid Phone Number'));
            return;
        }
        if (!serviceRequest.trim()) {
            res.json(getErrorMessage('Invalid Service Request'));
            return;
        }
        var re = /\S+@\S+\.\S+/;
        if ((!emailaddress.trim()) || (!re.test(emailaddress))) {
            res.json(getErrorMessage('Invalid email address'));
            return;
        }
    } catch (error) {
        logger.debug(error)
    }
    var fileName
    if (req.file) {
        fileName = req.file.filename
    }
    logger.debug('fileName:', fileName)

    let result = await helper.verifyCaptcha(recaptcha)
    if (!result) {
        res.json(getErrorMessage('Invalid recaptcha'));
        return;
    }

    var onDemandEmail = emailService.createOnDemandEmail(emailaddress, companyName, personincharge, phoneNo, serviceRequest);
    emailService.sendEmailWithAttachments(onDemandEmail, fileName);

    res.statusCode = 200;
    var response = "Successfully submitted"
    res.json({success: true, message: response});
    return;

});
//Defautl Health Check Router
app.get("/health", (req, res) => {
    res.statusCode = 200;
    let timestamp = new Date()
    res.json({timestamp: timestamp});
});
