module.exports = {
  entry: "./src/index-browser.js",
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
