const DAYS_2_YEARS = 730;

const daysBetween = (a, b) =>
  Math.abs(new Date(b) - new Date(a)) / (1000 * 60 * 60 * 24);

module.exports = {
  ruleId: 24,
  severity: "HIGH",
  requires: ["metadata"],

  run: ({ metadata }) => {
    if (!metadata) return [];

    const {
      previousVersionDate,
      latestVersionDate,
      previousMaintainer,
      currentMaintainer,
      linesAdded
    } = metadata;

    if (!previousVersionDate || !latestVersionDate) return [];

    const inactivityDays = daysBetween(
      previousVersionDate,
      latestVersionDate
    );

    const maintainerChanged =
      previousMaintainer &&
      currentMaintainer &&
      previousMaintainer !== currentMaintainer;

    const largeDiff = linesAdded && linesAdded > 1000;

    if (inactivityDays > DAYS_2_YEARS && (maintainerChanged || largeDiff)) {
      return [{
        rule: 24,
        severity: "HIGH",
        message: "Abandoned project resurrection detected",
        details: {
          inactivityDays: Math.floor(inactivityDays),
          maintainerChanged,
          linesAdded
        }
      }];
    }

    return [];
  }
};


// const DAYS_2_YEARS = 730;

// const daysBetween = (a, b) =>
//   Math.abs(new Date(b) - new Date(a)) / (1000 * 60 * 60 * 24);

// module.exports = (metadata) => {
//   const {
//     previousVersionDate,
//     latestVersionDate,
//     previousMaintainer,
//     currentMaintainer,
//     linesAdded
//   } = metadata;

//   if (!previousVersionDate || !latestVersionDate) return [];

//   const inactivityDays = daysBetween(
//     previousVersionDate,
//     latestVersionDate
//   );

//   const maintainerChanged =
//     previousMaintainer && currentMaintainer &&
//     previousMaintainer !== currentMaintainer;

//   const largeDiff = linesAdded && linesAdded > 1000;

//   // Detection logic
//   if (
//     inactivityDays > DAYS_2_YEARS &&
//     (maintainerChanged || largeDiff)
//   ) {
//     return [
//       {
//         rule: 24,
//         severity: "HIGH",
//         message:
//           "Possible abandoned project resurrection detected",
//         details: {
//           inactivityDays: Math.floor(inactivityDays),
//           maintainerChanged,
//           linesAdded
//         }
//       }
//     ];
//   }

//   return [];
// };
