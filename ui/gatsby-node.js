// Ignore Emacs lock files (https://github.com/gatsbyjs/gatsby/issues/25562).

exports.onCreateWebpackConfig = ({ actions }) => {
  actions.setWebpackConfig({
    devServer: {
      watchOptions: {
        ignored: /\.#|node_modules|~$/,
      },
    },
  });
};
