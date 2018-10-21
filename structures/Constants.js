const path = require('path');


module.exports = {
	lib_version: require(path.join(__dirname, "..", "package.json")).version,

	API : {
		HOST: "www.virustotal.com",
		PATH: "/vtapi/v2",



		FILES: {
			REPORT: "/file/report",
			SCAN: "/file/scan",
			UPLOAD_URL: "/file/upload_url", // For 200MB+ files
			RESCAN: "/file/rescan",
			DOWNLOAD: "/file/download",
			BEHAVIOUR: "/file/behaviour",
			TRAFFIC: "/file/network-traffic",
			FEED: "/file/feed",
			CLUSTERS: "/file/clusters",
			SEARCH: "/file/search"
		},

		URLS: {
			REPORT: "/url/report",
			SCAN: "/url/scan",
			SEARCH: "/url/search"
			
		},

		DOMAIN: {
			REPORT: "/domain/report"
		},
		IP: {
			REPORT: "/ip-address/report"
		},

		COMMENTS: {
			GET: "/comments/get",
			PUT: "/comments/put"
		}

	}

};