const mcl = require("mcl-wasm")

let args = process.argv[2]

mcl.init(mcl.BLS12_381)
    .then(() =>{
        let Q = mcl.hashAndMapToG2(args)
        console.log(Q.getStr().slice(2))
    })

