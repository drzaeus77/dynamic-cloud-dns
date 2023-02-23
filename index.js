/*jshint esversion: 6 */

const ipHelper = require('ip');
const {DNS} = require('@google-cloud/dns');
const settings = require('/secret/settings.json');
const { authenticator } = require('otplib');
const axios = require('axios');

const dns = new DNS();
/**
 * HTTP Cloud Function.
 *
 * @param {Object} req Cloud Function request context.
 * @param {Object} res Cloud Function response context.
 */
exports.updateHost = function(req, res) {
    var token = req.query.token || req.body.token;
    var ipv4 = req.query.ipv4 || req.body.ipv4;
    var ipv6 = req.query.ipv6 || req.body.ipv6;
    var host = req.query.host || req.body.host;
    var zone = req.query.zone || req.body.zone || settings.dnsZone;

    if (token != settings.secretToken) {
        respondWithError(401, 'unauthorized', 'Login Required', res);
        return;
    }

    if (!host) {
        respondWithError(400, 'missing host', 'Provide a valid host name', res);
        return;
    }

    if (!settings.allowedHosts.includes('*') && !settings.allowedHosts.includes(host)) {
        respondWithError(401, 'illegal host', 'Host "' + host + '" is not allowed', res);
        return;
    }

    if (!host.endsWith('.')) {
        host += '.';
    }

    if (!ipv4 && !ipv6) {
        var ipAddr = req.ip;
        if (ipHelper.isV4Format(ipAddr)) {
            ipv4 = ipAddr;
        } else if (ipHelper.isV6Format(ipAddr)) {
            ipv6 = ipAddr;
        } else {
            respondWithError(
                400,
                'missing ip',
                'Could not evaluate ip address. Please provide with request.',
                res
            );
            return;
        }
    }

    if (ipv4 && !ipHelper.isV4Format(ipv4)) {
        respondWithError(
            400,
            'illegal IPv4',
            'Could not parse IPv4 address: ' + ipv4,
            res
        );
        return;
    }

    if (ipv6 && !ipHelper.isV6Format(ipv6)) {
        respondWithError(
            400,
            'illegal IPv6',
            'Could not parse IPv6 address: ' + ipv6,
            res
        );
        return;
    }

    console.log({
        zone: zone,
        host: host,
        ipv4: ipv4,
        ipv6: ipv6
    });

    updateSonic(ipv4)
      .catch(err =>
        respondWithError(
            err.code || 500,
            err.title || 'Sonic error',
            err.message,
            res
          )
      );
    updateHosts(zone, host, ipv4, ipv6)
        .then(data => {
            res.status(200).json(data);
        })
        .catch(err =>
            respondWithError(
                err.code || 500,
                err.title || 'API error',
                err.message,
                res
            )
        );
};

function respondWithError(status, title, detail, res) {
    let err = { code: status, title: title, detail: detail };
    console.error(err);
    res.status(status).json(err);
}

function updateHosts(zone, host, ipv4, ipv6) {
    var dnsClient = dns;

    var dnsZone = dnsClient.zone(zone);

    return updateRecords(dnsZone, host, ipv4, ipv6)
        .then(() => {
            return {
                code: '200',
                values: {
                    host: host,
                    ipv4: ipv4,
                    ipv6: ipv6
                }
            };
    });
}

function getOldRecords(zone, host, ipv4, ipv6) {
    return zone
        .getRecords({ name: host, filterByTypes_: { A: ipv4, AAAA: ipv6 } })
        .then(data => {
            var oldRecord = data[0];
            if (oldRecord.length < 1) {
                throw {
                    code: 400,
                    title: 'illegal host',
                    message: 'Host "' + host + '" not found.'
                };
            }
            return oldRecord;
        });
}

function updateRecords(zone, host, ipv4, ipv6) {
    return getOldRecords(
        zone,
        host,
        typeof ipv4 != 'undefined',
        typeof ipv6 != 'undefined'
    ).then(oldRecords => {
        let newRecords = [];
        if (ipv4) {
            newRecords.push(
                zone.record('A', {
                    name: host,
                    ttl: settings.ttl,
                    data: ipv4
                })
            );
        }
        if (ipv6) {
            newRecords.push(
                zone.record('AAAA', {
                    name: host,
                    ttl: settings.ttl,
                    data: ipv6
                })
            );
        }
        return zone.createChange({
            add: newRecords,
            delete: oldRecords
        });
    });
}

function updateSonic(ipv4) {

  const instance = axios.create({
    baseURL: 'https://members.sonic.net/',
    timeout: 1000,
    maxRedirects: 0,
    withCredentials: true,
    validateStatus: function (status) {
      return status >= 200 && status <= 302
    },
    headers: {
      'Origin': 'https://members.sonic.net',
      'Accept': 'text/html,application/xhtml+xml,application/xml',
      'Accept-Language': 'Accept-Language: en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'Referer': 'https://members.sonic.net/',
      'Upgrade-Insecure-Requests': '1',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'same-origin',
      'Sec-Fetch-User': '?1',
    },
  });

  const params = new URLSearchParams({login: 'login', user: settings.sonicUser, pw: settings.sonicPw});

  var headers = {'content-type': 'application/x-www-form-urlencoded'};
  return instance.post('/', params, {headers})
    .then(function (response) {
      //console.log(response);
      if (response.status !== 302) {
        throw new Error('Expected 302, got ' + response.status);
      }
      const pcookie = (response.headers['set-cookie']).find(cookie => cookie.includes('PHPSESSID'))?.match(new RegExp(`^(PHPSESSID=.+?);`))?.[1];
      var cookie = pcookie;
      const vcookie = (response.headers['set-cookie']).find(cookie => cookie.includes('__vua'))?.match(new RegExp(`^(__vua=.+?);`))?.[1];
      cookie += '; ' + vcookie;
      Object.assign(headers, {Cookie: cookie});
      //console.log(headers);
      const mfaparams = new URLSearchParams({
        '2sv_auth': authenticator.generate(settings.sonicSecret),
        backup_code: '',
        '2sv_remember': 1
      });
      instance.post('/', mfaparams, {headers})
        .then(function (response) {
          //console.log(response);
          if (response.status !== 302) {
            throw new Error('Expected 302, got ' + response.status);
          }
          const mcookie = (response.headers['set-cookie']).find(cookie => cookie.includes('mt2FAToken'))?.match(new RegExp(`^(mt2FAToken=.+?);`))?.[1];
          cookie += '; ' + mcookie;
          Object.assign(headers, {Cookie: cookie});
          const ipv6params = new URLSearchParams({endpoint: ipv4, rdns_server: 'none', change: 1, action: 'step1'});
          instance.post('/labs/ipv6tunnel/#', ipv6params, {headers})
            .then(function (response) {
              console.log('Sonic updated: ' + response.statusText);
              //console.log(response);
            })
            .catch(function (error) {
              console.error(error);
            });
        })
        .catch(function (error) {
          console.error(error);
        });
    })
    .catch(function (error) {
      console.error(error);
    });
}

