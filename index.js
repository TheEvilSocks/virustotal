const https = require('https');
const querystring = require('querystring');
const fs = require('fs');

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
 	 * @arg {String} apiKey The VirusTotal API key. Used to make requests to the API.
 	 * @arg {Object} [optionalSettings] Optional settings.
 	 * @arg {Boolean} [optionalSettings.private] Make use of the Private API endpoints. READ MORE: https://developers.virustotal.com/v2.0/reference#public-vs-private-api
 	 * @arg {Object} [optionalSettings.dripperSettings] Used to configure the settings for the dripper which handles API ratelimits.
 	 * @arg {Number} [optionalSettings.ratelimit] The time (in seconds) for ratelimits.
 	 * @arg {Number} [optionalSettings.requests] The amount of requests per ratelimit time.
 	 * @arg {Number} [optionalSettings.latency] Network altency in milliseconds. Added on top of the ratelimit time basically.

 	*/

	constructor(apiKey, optionalSettings) {
		if(typeof optionalSettings === "boolean")
			optionalSettings = {private: optionalSettings};

 	 	optionalSettings = Object.assign(DEFAULT_SETTINGS, optionalSettings || {});

 	 	this.private = optionalSettings.private;

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
	 * @arg {String} resource The resource(s) to be retrieved. Should be a hash of a file. MD5, SHA-1 and SHA-256 are supported.
	 * @arg {Boolean} [allInfo=false] Request additional information such as virustotal metadata,  sandbox behaviour and more. NOTE: Must be using Private API
	 * @returns {Promise<Object>} 
 	*/
 	getFileReport(resource, allInfo=false){
 		return this.apiRequest("GET", Constants.API.FILES.REPORT, {resource: resource,allinfo: allInfo});
 	}

 	/**
 	 * Scan a file.
	 * @arg {String | Buffer} data The file contents to scan.
	 * @returns {Promise<Object>} 
 	*/
 	scanFile(data){

 		return new Promise( (fulfill, reject) => {

	 		if(!(data instanceof Buffer))
	 			data = Buffer.from(data);
	 		
	 		if(data.length > Constants.API.MAX_PRIVATE_FILESIZE && this.private){
	 			reject( { code: 400, message: "Filesize too big. Maximum size for PrivateAPI is 200MB." } );
	 			return;
	 		}

	 		if(data.length > Constants.API.MAX_PUBLIC_FILESIZE && this.private == false){
	 			reject( { code: 400, message: "Filesize too big. Maximum size for PublicAPI is 32MB." } );
	 			return;
	 		}

	 		if(data.length > Constants.API.MAX_PUBLIC_FILESIZE && this.private){
	 			this.getUploadUrl().then(url => {
	 				this.apiRequest("POST", url, { file: data.toString() }).then(fulfill,reject);
	 			});
	 			return;
	 		}

	 		this.apiRequest("POST", Constants.API.FILES.SCAN, { file: data.toString() }).then(fulfill,reject);
 		});

 	}

 	/**
 	 * Scan a file from a path.
	 * @arg {String} path The path the file is located at.
	 * @returns {Promise<Object>} 
 	*/
 	scanFilePath(path){
 		return new Promise( (fulfill, reject) => {
 			fs.readFile(path, (err, data) => {
 				if(err){
 					reject(err);
 				}else{
 					this.scanFile(data).then(fulfill, reject);
 				}
 			})
 		});
 	}


 	/**
 	 * [Private API] Get the upload url to upload files larger up to 200MB.
	 * @arg {String} path The path the file is located at.
	 * @returns {Promise<string>} 
 	*/
 	getUploadUrl(){
 		return new Promise( (fulfill, reject) => {
	 		if(!this.private){
	 			reject({message: "Please enable the private API when initializing this module."});
	 		}else{
	 			this.apiRequest("GET", Constants.API.FILES.UPLOAD_URL).then(res => {
	 				fulfill(res.upload_url);
	 			} ,reject);
	 		}
 		});
 	}



 	/**
 	 * Create an API request.
	 * @arg {String} method The HTTP method to make the request with. GET POST etc.
	 * @arg {String} path The endpoint to contact. DO NOT INCLUDE /vtapi/v2/
	 * @arg {Object} parameters Parameters to include in the request. For GET request these are URL parameters, for POST requests these are body parameters. API key is automatically included
	 * @returns {Promise<Object>} 
 	*/
 	apiRequest(method, path, parameters = {}){

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

 					let handleErr = () => {
 						var out = { code: res.statusCode, path: path, originalError: data };
 						switch(res.statusCode){
 							default:


 							case 403:
 								out.message = "Forbidden. Are you trying to use the Private API without a premium account?";
 							break;

 							case 404:
 								out.message = "Uhm, the page was not found. Could you report this to the library author?";
 							break;


 						}
 						
 						try{
 							out = Object.assign(out, JSON.parse(data));
 						}catch(err){}

 						reject( out );
 					}





 					if(res.statusCode == 200){
 						data = JSON.parse(data);

 						if('response_code' in data && data.response_code == 0){
 							handleErr();
 						}else{
 							fulfill( data );
 						}


 					}else{
 						handleErr();
 					}


 				});


 			});

			if(method === "POST"){
				req.end( querystring.stringify(Object.assign({apikey:this.apiKey}, parameters)) );
			}else{
				req.end();
			}

 		});

 	}


}



module.exports = VirusTotal;