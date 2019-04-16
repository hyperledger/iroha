#!/usr/bin/env groovy

def selectedBranchesCoverage(branches) {
	return env.GIT_LOCAL_BRANCH in branches
}

return this
