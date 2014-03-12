var expect = require('chai').expect;
var http = require('http');
var request = require('request');
var crypto = require('crypto');
var nock = require('nock');
var querystring = require('querystring');
var pubSubHubbub = require("../index");


var pubsub = pubSubHubbub.createServer({
  callbackUrl: 'http://localhost:8000/callback',
  secret: 'MyTopSecret',
  username: 'Test',
  password: 'P@ssw0rd',
  format: 'json'
});

var topic = 'http://test.com',
  response_body = "This is a response.",
  encrypted_secret = crypto.createHmac("sha1", pubsub.secret).update(topic).digest("hex");
  hub_encryption = crypto.createHmac('sha1', encrypted_secret).update(response_body).digest('hex');

var notification = function (){
  var options = {
    url: 'http://localhost:8000',
    headers: {
      'X-Hub-Signature': 'sha1='+hub_encryption,
      'X-PubSubHubbub-Callback': 'http://localhost:8000/callback',
      'hub.topic': 'http://test.com',
      'link': '<http://test.com>; rel="self", <http://pubsubhubbub.appspot.com/>; rel="hub"',
    },
    body: response_body
  }
  return request.post(options);
};

describe('pubsubhubbub server', function () {
  it('should exist', function () {
    expect(pubsub).to.exist;
  });

  it('should have passed options correctly', function () {
    expect(pubsub.callbackUrl).to.equal('http://localhost:8000/callback');
    expect(pubsub.secret).to.equal('MyTopSecret');
    expect(pubsub.format).to.equal('json');
  });

  it('should create an authentication object', function () {
    expect(pubsub.auth).to.exist;
    expect(pubsub.auth.user).to.equal("Test");
    expect(pubsub.auth.pass).to.equal("P@ssw0rd");

    expect(pubsub.auth).to.eql({
      'user': 'Test', 
      'pass': 'P@ssw0rd',
      'sendImmediately': true
    });
  });
});

describe('pubsubhubbub notification', function () {
  before(function () {
    pubsub.listen(8000);
  });

  after(function () {
    pubsub.server.close();
  });

  var eventFired = false;
  var data = null;

  pubsub.on('error', function (_data) {
      eventFired = true;
      data = _data;
  });

  pubsub.on('feed', function (_data) {
      eventFired = true;
      data = _data;  
  });

  it('should return 400 - no topic', function (done) {
    var options = {
      url: 'http://localhost:8000',
      headers: {
        'link': '<http://pubsubhubbub.appspot.com/>; rel="hub"'
      }
    };
    eventFired = false;
    data = null;

    request.post(options, function (err, res, body) {
      expect(res.statusCode).to.equal(400);
    });

    setTimeout(function () {
      expect(eventFired, 'eventFired should be true').to.equal(true);
      expect(data.code).to.equal(400);
      expect(data.message).to.equal('Bad Request');
      done();
    }, 20);
  });

  it('should return 403 - no X-Hub-Signature', function (done) {
    var options = {
      url: 'http://localhost:8000',
      headers: {
        'link': '<http://test.com>; rel="self", <http://pubsubhubbub.appspot.com/>; rel="hub"',
      }
    };
    eventFired = false;
    data = null;

    request.post(options, function (err, res, body) {
      expect(res.statusCode).to.equal(403);    
    });

    setTimeout(function () {
      expect(eventFired).to.equal(true);
      expect(data.code).to.equal(403);
      expect(data.message).to.equal('Forbidden');
      done();
    }, 20);
  });

  it('should return 202 - signature does not match', function (done) {
    var options = {
      url: 'http://localhost:8000',
      headers: {
        'X-Hub-Signature': 'sha1='+hub_encryption,
        'link': '<http://test.com>; rel="self", <http://pubsubhubbub.appspot.com/>; rel="hub"',
      },
      body: response_body + "potentially malicious content"
    }
    request.post(options, function (err, res, body) {
      expect(res.statusCode).to.equal(202);
      done();
    });
  });

  it('should return 204 - sucessful request', function (done) {
    var options = {
      url: 'http://localhost:8000',
      headers: {
        'X-Hub-Signature': 'sha1='+hub_encryption,
        'link': '<http://test.com>; rel="self", <http://pubsubhubbub.appspot.com/>; rel="hub"',
      },
      body: response_body
    }
    request.post(options, function (err, res, body) {
      expect(res.statusCode).to.equal(204);
      done();
    });
  });

  it('should emit a feed event - successful request', function (done) {
    eventFired = false;
    data = null;
    var options = {
      url: 'http://localhost:8000',
      headers: {
        'X-Hub-Signature': 'sha1='+hub_encryption,
        'link': '<http://test.com>; rel="self", <http://pubsubhubbub.appspot.com/>; rel="hub"',
      },
      body: response_body
    }
    request.post(options, function (err, res, body) {});

    setTimeout(function(){
      expect(eventFired).to.equal(true);
      expect(data.feed.toString()).to.equal(response_body);
      expect(data.topic.toString()).to.equal('http://test.com');
      done();
    }, 20);
  });

  it('should not emit a feed event - signature does not match', function (done) {
    eventFired = false;
    data = null;
    var options = {
      url: 'http://localhost:8000',
      headers: {
        'X-Hub-Signature': 'sha1='+hub_encryption,
        'link': '<http://test.com>; rel="self", <http://pubsubhubbub.appspot.com/>; rel="hub"',
      },
      body: response_body + "potentially malicious content"
    }
    request.post(options, function (err, res, body) {});

    setTimeout( function () {
      expect(eventFired).to.equal(false);
      expect(data).to.equal(null);
      done();
    }, 10);
  });
});

describe('pubsubhubbub verification', function () {
  before(function () {
    pubsub.listen(8000);
  });

  after(function () {
    pubsub.server.close();
  });

  var eventFired = false;
  var data = null;

  pubsub.on('subscribe', function (_data) {
    data = _data;
    eventFired = true;
  });

  pubsub.on('unsubscribe', function (_data) {
    data = _data;
    eventFired = true;
  });

  it('should send valid subscription request', function (done) {
    var scope = nock('http://test.com')
                    .filteringRequestBody(function (path) {
                      return querystring.parse(path)['hub.mode'];
                    })
                    .post('/feeds', 'subscribe')
                    .reply(202);

    pubsub.subscribe('http://test.com/topic', 'http://test.com/feeds', 'http://localhost:8000/callback');

    setTimeout( function () {
      expect(scope.isDone()).to.equal(true);
      done();
    }, 10);
  });
});