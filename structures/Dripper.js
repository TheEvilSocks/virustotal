'use strict';


/**
 * Used to handle ratelimited API requests.
 * @prop {Number} drips How many drips the dripper has dripped.
 * @prop {Number} dripLimit Amount of drips there can be within an interval.
 * @prop {Number} lastDrip Timestamp of last drip.
 * @prop {Number} lastFlush Timestamp of last flush.
 * @prop {Number} dripInterval Time in milliseconds to wait between flushing drips.
 */


 class Dripper {
 	/**
 	 * Make a dripper
 	 * @arg {Number} dripLimit Amount of requests per interval.
 	 * @arg {Number} dripInterval Amount of milliseconds to wait between flushing.
 	 * @arg {Number} [networkLatency] Extra time in milliseconds to add on top of dripInterval in case of network latency.
 	 */

 	 constructor(dripLimit, dripInterval, networkLatency) {
 	 	this.dripLimit = dripLimit;
 	 	this.dripInterval = dripInterval;
 	 	this.networkLatency = networkLatency || 0;

 	 	this.drips = 0; this.lastDrip = 0; this.lastFlush = 0; this.ratelimit = 0;
 	 	this._queue = [];
 	 }


 	 queue(cb, isPriority) {
 	 	if(!isPriority){
 	 		this._queue.push(cb);
 	 	}else{
 	 		this._queue.unshift(cb);
 	 	}
 	 	this.drip();
 	 }

 	 drip() {
 	 	if(this.busy || this._queue.length === 0)
 	 		return;

 	 	if(this.lastFlush + this.dripInterval + this.dripLimit * this.networkLatency < Date.now()){
 	 		this.lastFlush = Date.now();
 	 		this.drips = Math.max(0, this.drips - this.dripLimit);
 	 	}

 	 	while(this._queue.length && this.drips < this.dripLimit){
 	 		this.drips++;


 	 		let _drip = this._queue.shift();
 	 		let time = this.networkLatency + this.lastDrip - Date.now();

 	 		this.lastSend = Date.now() + Math.max(0, time);

 	 		setTimeout(() => {
 	 			_drip();
 	 		}, Math.max(0, time));

 	 	} // End while

 	 	if(this._queue.length && !this.busy){
 	 		
 	 		// Did the time var with an actual if-statement because I don't want a long ternary in the setTimeout
 	 		let time = this.networkLatency;

 	 		if(this.drips >= this.dripLimit)
 	 			time = Math.max(0, this.lastFlush + this.dripInterval + this.dripLimit * this.networkLatency - Date.now());
 	 		

 	 		this.busy = setTimeout(() => {
 	 			this.busy = null;
 	 			this.drip();
 	 		}, time);
 	 	}



 	 }


 }


 module.exports = Dripper;