/* Landing page */

// Requires.
var BleProfiler = require('./app/bin/bleprofiler')
var passkeyOptions = require('./app/bin/passkey-options.json')
var passkeyOpts = []
for(var pOpt in passkeyOptions){
    passkeyOpts.push(passkeyOptions[pOpt][1])
}

// Usage instructions.
var showHelp = function () {
    console.log('BLE PROFILER HELP')
    console.log('This tool tests the security level applied to characteristics on a BLE peripheral device.\n')
    console.log('Usage:\nsudo node index.js [-h] [-a] [-r] [-w] [-n] [-o filename] [-p opts]')
    console.log('  -h    Show help')
    console.log('  -a    Test all characteristics [Default=false]')
    console.log('  -r    Test only read access [Default=true]')
    console.log('  -w    Test only write access [Default=false]')
    console.log('  -n    Test only notify access [Default=false]')
    console.log('  -o    Name of output file (without extension)')
    console.log('  -p    Options for passkey entry')
    console.log('  opts  Possible options:')
    for(var pOpt in passkeyOptions){
        console.log('         ' + passkeyOptions[pOpt][1] + "   " + passkeyOptions[pOpt][0]);
    }
    console.log('\nExample:\n  sudo node index.js -a -w -p r')
    console.log('\n  This will test all characteristics for write access.\n  If passkey entry is required, the user will input the PIN that is displayed on the peripheral device.')
    console.log('\nNotes:\n  * "sudo" is not required on Windows.\n  * Order of arguments does not matter.\n')
    process.exit()    
}

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

// Check characteristic notifies.
var notify = false
if (process.argv.indexOf('-n') != -1) {
    notify = true
}

var getReadableDateTime = function () {
    var tempDate = new Date()
    var currMonth = '0' + (tempDate.getMonth() + 1)
    currMonth = currMonth.slice(-2)
    var currDate = '0' + tempDate.getDate()
    currDate = currDate.slice(-2)
    var currHour = '0' + tempDate.getHours()
    currHour = currHour.slice(-2)
    var currMin = '00' + tempDate.getMinutes()
    currMin = currMin.slice(-2)
    var currSec = '00' + tempDate.getSeconds()
    currSec = currSec.slice(-2)
    var outDate = '' + tempDate.getFullYear() + currMonth + currDate + '_' + currHour + currMin + currSec
    return outDate
}
// Check output file name.
var outputFileName = false
if (process.argv.indexOf('-o') != -1) {
    var indexOfO = process.argv.indexOf('-o')
    outputFileName = process.argv[indexOfO + 1] + '.json'
} else {
    var currDate = getReadableDateTime()
    outputFileName = 'output_' + currDate + '.json'
}

// Limit checks to characteristics that have the relevant access type in their properties list.
var limitToProperties = true 
if (process.argv.indexOf('-a') != -1) {
    limitToProperties = false
}

// Passkey entry options.
var passkeyEntry = 'u'
var passkeyValue = null
if (process.argv.indexOf('-p') != -1) {
    var indexOfP = process.argv.indexOf('-p')
    var passkeyChoice = process.argv[indexOfP + 1]
    if (passkeyOpts.indexOf(passkeyChoice) > 0) {
        passkeyEntry = passkeyChoice
    } else {
        // Assume the next value is the PIN.
        passkeyValue = passkeyChoice
    }
}

// Help
if (process.argv.indexOf('-h') != -1) {
    showHelp()
} else {
    console.log('BLE Security Profiler\n')
    if (passkeyValue !== null) {
        console.log('Taking passkey to be: ' + passkeyChoice + '\n')
    }
}

// Create new BleProfiler instance.
var bleProfiler = new BleProfiler(limitToProperties, read, write, notify, passkeyEntry, passkeyValue, outputFileName)

// Start.
bleProfiler.scanForDevices(5000)
