module.exports = {
  entry: "../src/index.js",
  mode: "production",
  output: {
    path: __dirname + '/',
    library: 'bls',
    libraryTarget: 'umd',
    filename: 'bls.js'
  },
/*
  resolve: {
    fallback: {
      path: false,
      fs: false,
      crypto: false,
    },
  },
*/
  target: "web"
};
