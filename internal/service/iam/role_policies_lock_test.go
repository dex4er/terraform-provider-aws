// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iam_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	tfiam "github.com/hashicorp/terraform-provider-aws/internal/service/iam"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccIAMRolePoliciesLock_basic(t *testing.T) {
	ctx := acctest.Context(t)

	var role types.Role
	var rolePolicy string
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_iam_role_policies_lock.test"
	roleResourceName := "aws_iam_role.test"
	rolePolicyResourceName := "aws_iam_role_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.IAMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckRolePoliciesLockDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccRolePoliciesLockConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRoleExists(ctx, roleResourceName, &role),
					testAccCheckRolePolicyExists(ctx, rolePolicyResourceName, &rolePolicy),
					testAccCheckRolePoliciesLockExists(ctx, resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "role_name", roleResourceName, names.AttrName),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_names.*", rolePolicyResourceName, names.AttrName),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccRolePoliciesLockImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "role_name",
			},
		},
	})
}

func TestAccIAMRolePoliciesLock_disappears_Role(t *testing.T) {
	ctx := acctest.Context(t)

	var role types.Role
	var rolePolicy string
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_iam_role_policies_lock.test"
	roleResourceName := "aws_iam_role.test"
	rolePolicyResourceName := "aws_iam_role_policy.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.IAMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckRolePoliciesLockDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccRolePoliciesLockConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRoleExists(ctx, roleResourceName, &role),
					testAccCheckRolePolicyExists(ctx, rolePolicyResourceName, &rolePolicy),
					testAccCheckRolePoliciesLockExists(ctx, resourceName),
					// Inline policy must be deleted before the role can be
					acctest.CheckResourceDisappears(ctx, acctest.Provider, tfiam.ResourceRolePolicy(), rolePolicyResourceName),
					acctest.CheckResourceDisappears(ctx, acctest.Provider, tfiam.ResourceRole(), roleResourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccIAMRolePoliciesLock_multiple(t *testing.T) {
	ctx := acctest.Context(t)

	var role types.Role
	var rolePolicy string
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_iam_role_policies_lock.test"
	roleResourceName := "aws_iam_role.test"
	rolePolicyResourceName := "aws_iam_role_policy.test"
	rolePolicyResourceName2 := "aws_iam_role_policy.test2"
	rolePolicyResourceName3 := "aws_iam_role_policy.test3"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.IAMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckRolePoliciesLockDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccRolePoliciesLockConfig_multiple(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRoleExists(ctx, roleResourceName, &role),
					testAccCheckRolePolicyExists(ctx, rolePolicyResourceName, &rolePolicy),
					testAccCheckRolePoliciesLockExists(ctx, resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "role_name", roleResourceName, names.AttrName),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_names.*", rolePolicyResourceName, names.AttrName),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_names.*", rolePolicyResourceName2, names.AttrName),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_names.*", rolePolicyResourceName3, names.AttrName),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccRolePoliciesLockImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "role_name",
			},
			{
				Config: testAccRolePoliciesLockConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRoleExists(ctx, roleResourceName, &role),
					testAccCheckRolePolicyExists(ctx, rolePolicyResourceName, &rolePolicy),
					testAccCheckRolePoliciesLockExists(ctx, resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "role_name", roleResourceName, names.AttrName),
					resource.TestCheckTypeSetElemAttrPair(resourceName, "policy_names.*", rolePolicyResourceName, names.AttrName),
				),
			},
		},
	})
}

func TestAccIAMRolePoliciesLock_empty(t *testing.T) {
	ctx := acctest.Context(t)

	var role types.Role
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_iam_role_policies_lock.test"
	roleResourceName := "aws_iam_role.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.IAMServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckRolePoliciesLockDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccRolePoliciesLockConfig_empty(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRoleExists(ctx, roleResourceName, &role),
					testAccCheckRolePoliciesLockExists(ctx, resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "role_name", roleResourceName, names.AttrName),
					resource.TestCheckResourceAttr(resourceName, "policy_names.#", acctest.Ct0),
				),
				// The empty `policy_names` argument in the lock will remove the
				// inline policy defined in this configuration, so a diff is expected
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCheckRolePoliciesLockDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).IAMClient(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_iam_role_policies_lock" {
				continue
			}

			roleName := rs.Primary.Attributes["role_name"]
			_, err := tfiam.FindRolePoliciesByName(ctx, conn, roleName)
			if errs.IsA[*types.NoSuchEntityException](err) {
				return nil
			}
			if err != nil {
				return create.Error(names.IAM, create.ErrActionCheckingDestroyed, tfiam.ResNameRolePoliciesLock, rs.Primary.ID, err)
			}

			return create.Error(names.IAM, create.ErrActionCheckingDestroyed, tfiam.ResNameRolePoliciesLock, rs.Primary.ID, errors.New("not destroyed"))
		}

		return nil
	}
}

func testAccCheckRolePoliciesLockExists(ctx context.Context, name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return create.Error(names.IAM, create.ErrActionCheckingExistence, tfiam.ResNameRolePoliciesLock, name, errors.New("not found"))
		}

		roleName := rs.Primary.Attributes["role_name"]
		if roleName == "" {
			return create.Error(names.IAM, create.ErrActionCheckingExistence, tfiam.ResNameRolePoliciesLock, name, errors.New("not set"))
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).IAMClient(ctx)
		out, err := tfiam.FindRolePoliciesByName(ctx, conn, roleName)
		if err != nil {
			return create.Error(names.IAM, create.ErrActionCheckingExistence, tfiam.ResNameRolePoliciesLock, roleName, err)
		}

		policyCount := rs.Primary.Attributes["policy_names.#"]
		if policyCount != fmt.Sprint(len(out)) {
			return create.Error(names.IAM, create.ErrActionCheckingExistence, tfiam.ResNameRolePoliciesLock, roleName, errors.New("unexpected policy_names count"))
		}

		return nil
	}
}

func testAccRolePoliciesLockImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("Not found: %s", resourceName)
		}

		return rs.Primary.Attributes["role_name"], nil
	}
}

func testAccRolePoliciesLockConfigBase(rName string) string {
	return fmt.Sprintf(`
data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "inline" {
  statement {
    actions   = ["s3:ListBucket"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "test" {
  name               = %[1]q
  assume_role_policy = data.aws_iam_policy_document.trust.json
}

resource "aws_iam_role_policy" "test" {
  name   = %[1]q
  role   = aws_iam_role.test.name
  policy = data.aws_iam_policy_document.inline.json
}
`, rName)
}

func testAccRolePoliciesLockConfig_basic(rName string) string {
	return acctest.ConfigCompose(
		testAccRolePoliciesLockConfigBase(rName),
		`
resource "aws_iam_role_policies_lock" "test" {
  role_name    = aws_iam_role.test.name
  policy_names = [aws_iam_role_policy.test.name]
}
`)
}

func testAccRolePoliciesLockConfig_multiple(rName string) string {
	return acctest.ConfigCompose(
		testAccRolePoliciesLockConfigBase(rName),
		fmt.Sprintf(`
resource "aws_iam_role_policy" "test2" {
  name   = "%[1]s-2"
  role   = aws_iam_role.test.name
  policy = data.aws_iam_policy_document.inline.json
}

resource "aws_iam_role_policy" "test3" {
  name   = "%[1]s-3"
  role   = aws_iam_role.test.name
  policy = data.aws_iam_policy_document.inline.json
}

resource "aws_iam_role_policies_lock" "test" {
  role_name    = aws_iam_role.test.name
  policy_names = [
    aws_iam_role_policy.test.name,
    aws_iam_role_policy.test2.name,
    aws_iam_role_policy.test3.name,
  ]
}
`, rName))
}

func testAccRolePoliciesLockConfig_empty(rName string) string {
	return acctest.ConfigCompose(
		testAccRolePoliciesLockConfigBase(rName),
		`
resource "aws_iam_role_policies_lock" "test" {
  # Wait until the inline policy is created, then provision
  # the lock which will remove it. This creates a diff on
  # on the next plan (to re-create aws_iam_role_policy.test)
  # which the test can check for.
  depends_on = [aws_iam_role_policy.test]

  role_name    = aws_iam_role.test.name
  policy_names = []
}
`)
}
