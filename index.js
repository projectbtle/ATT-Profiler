/* Landing page */

// Requires.
var BleProfiler = require('./app/bin/bleprofiler')

/* Handle input arguments. */

// Check characteristic reads.
var read = false
if (process.argv.indexOf('-r') != -1) {
    read = true
}
// Check characteristic writes.
var write = false
if (process.argv.indexOf('-w') != -1) {
    write = true
}

// Check characteristic reads.
var notify = false
if (process.argv.indexOf('-n') != -1) {
    notify = true
}

// Limit checks to characteristics that have the relevant access type in their properties list.
var limitToProperties = true 
if (process.argv.indexOf('-a') != -1) {
    limitToProperties = false
}

// Create new BleProfiler instance.
var bleProfiler = new BleProfiler(limitToProperties, read, write, notify)

// Start.
bleProfiler.scanForDevices(5000)
