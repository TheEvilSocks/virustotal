const https = require('https');
const querystring = require('querystring');

const Constants = require('./structures/Constants.js');
const Dripper = require('./structures/Dripper.js');




const DEFAULT_SETTINGS = {
	private: false,
	dripperSettings: {
		ratelimit: 60,
		requests: 4
	}
}



class VirusTotal {


 	/**
 	 * Create a new API client
 	 * @arg {string} apiKey The VirusTotal API key. Used to make requests to the API.
 	 * @arg {object} [optionalSettings] Optional settings.
 	 * @arg {boolean} [optionalSettings.private] Make use of the Private API endpoints. READ MORE: https://developers.virustotal.com/v2.0/reference#public-vs-private-api
 	 * @arg {object} [optionalSettings.dripperSettings] Used to configure the settings for the dripper which handles API ratelimits.
 	 * @arg {number} [optionalSettings.ratelimit] The time (in seconds) for ratelimits.
 	 * @arg {number} [optionalSettings.requests] The amount of requests per ratelimit time.
 	 * @arg {number} [optionalSettings.latency] Network altency in milliseconds. Added on top of the ratelimit time basically.

 	*/

	constructor(apiKey, optionalSettings) {
 	 	optionalSettings = Object.assign(DEFAULT_SETTINGS, optionalSettings || {});

 	 	this.apiKey = apiKey;

 	 	this.dripper = new Dripper(optionalSettings.dripperSettings.requests, optionalSettings.dripperSettings.ratelimit, optionalSettings.dripperSettings.latency);

 	 	this._options = {
 	 		hostname: Constants.API.HOST,
			port: 443,
			headers: {
				'User-Agent': `NodeJS VirusTotal/VirusTotal v${Constants.lib_version} - VirusTotal API library`
			}
		};

		this.Constants = Constants;
 	}



 	/**
 	 * Get a report of a file.
	 * @arg {string} resource The resource(s) to be retrieved. Should be a hash of a file. MD5, SHA-1 and SHA-256 are supported.
	 * @arg {boolean} [allInfo=false] Request additional information such as virustotal metadata,  sandbox behaviour and more. NOTE: Must be using Private API
	 * @returns {Promise<Object>} 
 	*/
 	getFileReport(resource, allInfo=false){
 		return this.apiRequest("GET", Constants.API.FILES.REPORT, {resource: resource,allinfo: allInfo});
 	}

 	/**
 	 * Create an API request.
	 * @arg {string} method The HTTP method to make the request with. GET POST etc.
	 * @arg {string} path The endpoint to contact. DO NOT INCLUDE /vtapi/v2/
	 * @arg {object} parameters Parameters to include in the request. For GET request these are URL parameters, for POST requests these are body parameters. API key is automatically included
	 * @returns {Promise<Object>} 
 	*/
 	apiRequest(method, path, parameters){
		return new Promise((fulfill, reject) => {
			this.dripper.queue(() => {
				this._apiRequest(method, path, parameters).then(fulfill, reject);
			});
		});
 	}

 	_apiRequest(method, path, parameters){

 		return new Promise( (fulfill, reject) => {
 			method = method.toUpperCase();
 			
 			let url_params = "";

 			if(method == "GET"){
 				url_params += `?apikey=${this.apiKey}`;


 				url_params += Object.keys(parameters).map( key => {
 					return `&${key}=${parameters[key]}`;
 				});
 			}


 			var opts = {
 				path: Constants.API.PATH + path + url_params,
 				method: method
 			};

 			if(method === "POST"){
 				opts = Object.assign(opts, {headers: {"Content-Type": "application/x-www-form-urlencoded"}})
 			}

 			opts = Object.assign(opts, this._options);

 			var req = https.request(opts, res => {
 				var data = "";

 				res.on('data', chunk => {
 					data += chunk;
 				});

 				res.on('error', err => {
 					reject(err);
 				});

 				res.on('close', () => {
 					if(res.statusCode == 200){
 						fulfill( JSON.parse(data) );
 					}else{
 						let out = { code: res.statusCode };
 						try{
 							out = Object.assign(out, JSON.parse(data));
 						}catch(err){}

 						reject( out );
 					}
 				});

 			});

			if(method === "POST"){
				req.end( querystring.stringify(parameters) );
			}else{
				req.end();
			}

 		});

 	}


}



module.exports = VirusTotal;