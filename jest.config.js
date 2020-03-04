module.exports = {
  verbose: true,
  transform: {
    "^.+\\.ts?$": "ts-jest"
  },
  testEnvironment: "node",
  testRegex: "/tests/.*\\.(test|spec)?\\.(ts|tsx)$",
  moduleFileExtensions: ["ts", "js", "json", "node"],
  coverageDirectory: "./coverage/",
  collectCoverage: true
};
