@Library('jenkins-library@feature/DOPS-2261/iroha2-pr-deploy') _

def pipeline = new org.argoPRDeploy.AppPipeline(steps: this,
    k8sPrDeploy: true,
    buildEnvironment: buildEnvironment,
    vaultPrPath: "argocd-cc/src/charts/iroha2/environments/tachi/",
    vaultUser: "iroha2-rw",
    vaultCredId: "iroha2VaultCreds",
    valuesDestPath: "argocd-cc/src/charts/iroha2/",
    devValuesPath: "dev/dev/",
    initialSecretName: "iroha2-eso-base",
    initialNameSpace: "iroha2-dev",
    targetNameSpace: "iroha2-${env.CHANGE_ID}-dev",
    targetSecretName: "iroha2-${env.CHANGE_ID}-dev-eso-base",
    ingressEnabled: false
)
pipeline.runPipeline()