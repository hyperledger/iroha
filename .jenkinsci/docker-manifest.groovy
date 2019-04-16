#!/usr/bin/env groovy

def manifestSupportEnabled() {
	def dockerVersion = sh(script: "docker -v", returnStdout: true).trim()
	def experimentalEnabled = sh(script: "grep -i experimental ~/.docker/config.json", returnStatus: true)
	return experimentalEnabled == 0 && dockerVersion ==~ /^Docker version 18.*$/

}

def manifestCreate(manifestListName, manifests) {
	sh "docker manifest create ${manifestListName} ${manifests.join(' ')}"
}

def manifestAnnotate(manifestListName, manifestsWithFeatures) {
	manifestsWithFeatures.each {
		sh """
			docker manifest annotate ${manifestListName} ${it['manifest']} --arch "${it['arch']}" \
			--os "${it['os']}" --os-features "${it['osfeatures'].join(',')}" --variant "${it['variant']}"
		"""
	}
}

def manifestPush(manifestListName, dockerRegistryLogin, dockerRegistryPassword) {
	sh "docker login -u '${dockerRegistryLogin}' -p '${dockerRegistryPassword}'"
	sh "docker manifest push --purge ${manifestListName}"
}

return this
