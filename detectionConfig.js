export const detectionConfig = {
  scheduler: {
    rescanIntervalSeconds: 120,
  },
  rolePermissions: {
    viewer: ["login", "view"],
    editor: ["login", "view", "edit", "download", "export"],
    admin: [
      "login",
      "view",
      "edit",
      "download",
      "export",
      "delete",
      "manage_users",
      "change_role",
      "delete_user",
    ],
  },
  rules: {
    bulkDataAccess: {
      windowMinutes: 15,
      actions: ["download", "export"],
      countThreshold: 30,
      historicalWindowDays: 7,
      historicalMultiplier: 5,
      minimumCountForBaseline: 10,
      severity: "high",
    },
    accessOutsideRole: {
      severity: "medium",
    },
    scrapingPattern: {
      windowMinutes: 10,
      distinctResourceThreshold: 40,
      severity: "high",
    },
    privilegeEscalation: {
      adminOnlyActions: ["manage_users", "change_role", "delete_user", "access_admin"],
      adminEndpointKeywords: ["/admin", "admin/"],
      severity: "high",
    },
    botLikeTiming: {
      lastNActions: 12,
      minRequiredGaps: 6,
      avgGapThresholdSeconds: 1.2,
      stddevGapThresholdSeconds: 0.2,
      severity: "medium",
    },
    endpointProbing: {
      windowMinutes: 10,
      statusCodes: [403, 404],
      threshold: 20,
      severity: "medium",
    },
    ipTrafficSpike: {
      windowMinutes: 5,
      threshold: 250,
      severity: "high",
    },
    knownMaliciousIp: {
      abuseScoreThreshold: 70,
      cacheTtlMinutes: 60,
      severity: "high",
    },
  },
};
