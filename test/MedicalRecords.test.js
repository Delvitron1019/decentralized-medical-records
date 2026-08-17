const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");

/**
 * Access-control contracts are judged on what they REFUSE, not what they allow.
 * Most of these tests assert a revert. A suite that only proves the happy path
 * proves nothing about a permission system.
 */
describe("MedicalRecords", function () {
  const HASH_A = ethers.keccak256(ethers.toUtf8Bytes("encrypted-payload-a"));
  const HASH_B = ethers.keccak256(ethers.toUtf8Bytes("encrypted-payload-b"));

  const RecordType = {
    Diagnosis: 0, LabResult: 1, Imaging: 2, Prescription: 3, DischargeSummary: 4,
  };
  const Permission = { None: 0, Read: 1, Write: 2 };

  async function deploy() {
    const [admin, patient, otherPatient, hospital, hospital2, insurer, stranger] =
      await ethers.getSigners();

    const Factory = await ethers.getContractFactory("MedicalRecords");
    const contract = await Factory.deploy(admin.address);

    const HOSPITAL_ROLE = await contract.HOSPITAL_ROLE();
    const INSURER_ROLE  = await contract.INSURER_ROLE();

    await contract.connect(admin).grantRole(HOSPITAL_ROLE, hospital.address);
    await contract.connect(admin).grantRole(HOSPITAL_ROLE, hospital2.address);
    await contract.connect(admin).grantRole(INSURER_ROLE, insurer.address);

    return { contract, admin, patient, otherPatient, hospital, hospital2,
             insurer, stranger, HOSPITAL_ROLE, INSURER_ROLE };
  }

  describe("roles", function () {
    it("assigns the admin role at deployment", async function () {
      const { contract, admin } = await loadFixture(deploy);
      const DEFAULT_ADMIN_ROLE = await contract.DEFAULT_ADMIN_ROLE();
      expect(await contract.hasRole(DEFAULT_ADMIN_ROLE, admin.address)).to.equal(true);
    });

    it("refuses role grants from non-admins", async function () {
      const { contract, stranger, HOSPITAL_ROLE } = await loadFixture(deploy);
      await expect(
        contract.connect(stranger).grantRole(HOSPITAL_ROLE, stranger.address)
      ).to.be.revertedWithCustomError(contract, "AccessControlUnauthorizedAccount");
    });
  });

  describe("writing records", function () {
    it("lets a hospital write once the patient has granted write access", async function () {
      const { contract, patient, hospital } = await loadFixture(deploy);
      await contract.connect(patient).grantAccess(hospital.address, Permission.Write);

      await expect(
        contract.connect(hospital).addRecord(patient.address, HASH_A, RecordType.Diagnosis)
      ).to.emit(contract, "RecordAdded")
       .withArgs(patient.address, 0, hospital.address, RecordType.Diagnosis, HASH_A);

      expect(await contract.recordCount(patient.address)).to.equal(1);
    });

    it("refuses a hospital with no grant", async function () {
      const { contract, patient, hospital } = await loadFixture(deploy);
      await expect(
        contract.connect(hospital).addRecord(patient.address, HASH_A, RecordType.Diagnosis)
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("refuses a hospital holding only read access", async function () {
      const { contract, patient, hospital } = await loadFixture(deploy);
      await contract.connect(patient).grantAccess(hospital.address, Permission.Read);
      await expect(
        contract.connect(hospital).addRecord(patient.address, HASH_A, RecordType.Diagnosis)
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("refuses an insurer, even with write access granted", async function () {
      // An insurer must never be able to author a clinical record. The role
      // gate stops this before the permission check is even reached.
      const { contract, patient, insurer } = await loadFixture(deploy);
      await contract.connect(patient).grantAccess(insurer.address, Permission.Write);
      await expect(
        contract.connect(insurer).addRecord(patient.address, HASH_A, RecordType.Diagnosis)
      ).to.be.revertedWithCustomError(contract, "AccessControlUnauthorizedAccount");
    });
  });

  describe("reading records", function () {
    async function withRecord() {
      const ctx = await loadFixture(deploy);
      await ctx.contract.connect(ctx.patient).grantAccess(ctx.hospital.address, Permission.Write);
      await ctx.contract.connect(ctx.hospital)
        .addRecord(ctx.patient.address, HASH_A, RecordType.LabResult);
      return ctx;
    }

    it("lets the patient read their own record", async function () {
      const { contract, patient } = await withRecord();
      const r = await contract.connect(patient).getRecord(patient.address, 0);
      expect(r[0]).to.equal(HASH_A);
    });

    it("lets the authoring hospital read it back", async function () {
      const { contract, patient, hospital } = await withRecord();
      const r = await contract.connect(hospital).getRecord(patient.address, 0);
      expect(r[1]).to.equal(hospital.address);
    });

    it("refuses a stranger", async function () {
      const { contract, patient, stranger } = await withRecord();
      await expect(
        contract.connect(stranger).getRecord(patient.address, 0)
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("refuses an insurer with no grant", async function () {
      const { contract, patient, insurer } = await withRecord();
      await expect(
        contract.connect(insurer).getRecord(patient.address, 0)
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("refuses a second hospital that did not author the record", async function () {
      const { contract, patient, hospital2 } = await withRecord();
      await expect(
        contract.connect(hospital2).getRecord(patient.address, 0)
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("allows an insurer once the patient shares that single record", async function () {
      const { contract, patient, insurer } = await withRecord();
      await contract.connect(patient).shareRecord(0, insurer.address);
      const r = await contract.connect(insurer).getRecord(patient.address, 0);
      expect(r[0]).to.equal(HASH_A);
    });

    it("keeps a record-level share scoped to that record only", async function () {
      // The point of per-record sharing: an insurer given one lab result must
      // not thereby see the patient's whole history.
      const { contract, patient, hospital, insurer } = await withRecord();
      await contract.connect(hospital)
        .addRecord(patient.address, HASH_B, RecordType.Imaging);
      await contract.connect(patient).shareRecord(0, insurer.address);

      await contract.connect(insurer).getRecord(patient.address, 0);   // allowed
      await expect(
        contract.connect(insurer).getRecord(patient.address, 1)
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("reverts for a record that does not exist", async function () {
      const { contract, patient } = await withRecord();
      await expect(
        contract.connect(patient).getRecord(patient.address, 99)
      ).to.be.revertedWithCustomError(contract, "RecordNotFound");
    });
  });

  describe("revocation", function () {
    it("stops further reads after a standing grant is revoked", async function () {
      const { contract, patient, hospital, insurer } = await loadFixture(deploy);
      await contract.connect(patient).grantAccess(hospital.address, Permission.Write);
      await contract.connect(hospital).addRecord(patient.address, HASH_A, RecordType.Diagnosis);
      await contract.connect(patient).grantAccess(insurer.address, Permission.Read);

      await contract.connect(insurer).getRecord(patient.address, 0);   // allowed

      await contract.connect(patient).revokeAccess(insurer.address);
      await expect(
        contract.connect(insurer).getRecord(patient.address, 0)
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("stops a hospital writing further records after revocation", async function () {
      const { contract, patient, hospital } = await loadFixture(deploy);
      await contract.connect(patient).grantAccess(hospital.address, Permission.Write);
      await contract.connect(hospital).addRecord(patient.address, HASH_A, RecordType.Diagnosis);

      await contract.connect(patient).revokeAccess(hospital.address);
      await expect(
        contract.connect(hospital).addRecord(patient.address, HASH_B, RecordType.Imaging)
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("leaves already-authored records readable by their author", async function () {
      // Documenting real behaviour rather than asserting a guarantee the chain
      // cannot make: revocation is forward-looking. The hospital that wrote a
      // record retains provenance access to it.
      const { contract, patient, hospital } = await loadFixture(deploy);
      await contract.connect(patient).grantAccess(hospital.address, Permission.Write);
      await contract.connect(hospital).addRecord(patient.address, HASH_A, RecordType.Diagnosis);
      await contract.connect(patient).revokeAccess(hospital.address);

      const r = await contract.connect(hospital).getRecord(patient.address, 0);
      expect(r[0]).to.equal(HASH_A);
    });

    it("revokes a per-record share without touching other records", async function () {
      const { contract, patient, hospital, insurer } = await loadFixture(deploy);
      await contract.connect(patient).grantAccess(hospital.address, Permission.Write);
      await contract.connect(hospital).addRecord(patient.address, HASH_A, RecordType.Diagnosis);
      await contract.connect(patient).shareRecord(0, insurer.address);
      await contract.connect(patient).revokeRecordShare(0, insurer.address);

      await expect(
        contract.connect(insurer).getRecord(patient.address, 0)
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });
  });

  describe("isolation between patients", function () {
    it("does not leak one patient's records via another patient's grant", async function () {
      const { contract, patient, otherPatient, hospital, insurer } = await loadFixture(deploy);
      await contract.connect(patient).grantAccess(hospital.address, Permission.Write);
      await contract.connect(otherPatient).grantAccess(hospital.address, Permission.Write);
      await contract.connect(hospital).addRecord(patient.address, HASH_A, RecordType.Diagnosis);
      await contract.connect(hospital).addRecord(otherPatient.address, HASH_B, RecordType.Imaging);

      // Insurer trusted by otherPatient must not thereby reach patient's data.
      await contract.connect(otherPatient).grantAccess(insurer.address, Permission.Read);
      await expect(
        contract.connect(insurer).getRecord(patient.address, 0)
      ).to.be.revertedWithCustomError(contract, "NotAuthorized");
    });

    it("keeps record ids independent per patient", async function () {
      const { contract, patient, otherPatient, hospital } = await loadFixture(deploy);
      await contract.connect(patient).grantAccess(hospital.address, Permission.Write);
      await contract.connect(otherPatient).grantAccess(hospital.address, Permission.Write);
      await contract.connect(hospital).addRecord(patient.address, HASH_A, RecordType.Diagnosis);
      await contract.connect(hospital).addRecord(otherPatient.address, HASH_B, RecordType.Imaging);

      expect(await contract.recordCount(patient.address)).to.equal(1);
      expect(await contract.recordCount(otherPatient.address)).to.equal(1);
    });
  });

  describe("guards", function () {
    it("refuses a self-grant", async function () {
      const { contract, patient } = await loadFixture(deploy);
      await expect(
        contract.connect(patient).grantAccess(patient.address, Permission.Write)
      ).to.be.revertedWithCustomError(contract, "CannotGrantToSelf");
    });

    it("refuses granting the None permission", async function () {
      const { contract, patient, hospital } = await loadFixture(deploy);
      await expect(
        contract.connect(patient).grantAccess(hospital.address, Permission.None)
      ).to.be.revertedWithCustomError(contract, "InvalidPermission");
    });

    it("refuses sharing a record that does not exist", async function () {
      const { contract, patient, insurer } = await loadFixture(deploy);
      await expect(
        contract.connect(patient).shareRecord(0, insurer.address)
      ).to.be.revertedWithCustomError(contract, "RecordNotFound");
    });

    it("blocks writes while paused but still allows revocation", async function () {
      // A patient must always be able to withdraw consent, even during an
      // incident freeze. Blocking revocation while paused would make the
      // pause switch a tool against the patient.
      const { contract, admin, patient, hospital } = await loadFixture(deploy);
      await contract.connect(patient).grantAccess(hospital.address, Permission.Write);
      await contract.connect(admin).pause();

      await expect(
        contract.connect(hospital).addRecord(patient.address, HASH_A, RecordType.Diagnosis)
      ).to.be.revertedWithCustomError(contract, "EnforcedPause");

      await expect(contract.connect(patient).revokeAccess(hospital.address)).to.not.be.reverted;
    });

    it("refuses pause from a non-admin", async function () {
      const { contract, stranger } = await loadFixture(deploy);
      await expect(
        contract.connect(stranger).pause()
      ).to.be.revertedWithCustomError(contract, "AccessControlUnauthorizedAccount");
    });
  });
});
