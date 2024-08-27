// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awstypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	intflex "github.com/hashicorp/terraform-provider-aws/internal/flex"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	"github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @FrameworkResource("aws_iam_role_policies_lock", name="Role Policies Lock")
func newResourceRolePoliciesLock(_ context.Context) (resource.ResourceWithConfigure, error) {
	return &resourceRolePoliciesLock{}, nil
}

const (
	ResNameRolePoliciesLock = "Role Policies Lock"
)

type resourceRolePoliciesLock struct {
	framework.ResourceWithConfigure
	framework.WithNoOpDelete
}

func (r *resourceRolePoliciesLock) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "aws_iam_role_policies_lock"
}

func (r *resourceRolePoliciesLock) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"role_name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"policy_names": schema.SetAttribute{
				ElementType: types.StringType,
				Required:    true,
			},
		},
	}
}

func (r *resourceRolePoliciesLock) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan resourceRolePoliciesLockData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policyNames []string
	resp.Diagnostics.Append(plan.PolicyNames.ElementsAs(ctx, &policyNames, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.syncAttachments(ctx, plan.RoleName.ValueString(), policyNames)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.IAM, create.ErrActionCreating, ResNameRolePoliciesLock, plan.RoleName.String(), err),
			err.Error(),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceRolePoliciesLock) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	conn := r.Meta().IAMClient(ctx)

	var state resourceRolePoliciesLockData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := findRolePoliciesByName(ctx, conn, state.RoleName.ValueString())
	if tfresource.NotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.IAM, create.ErrActionReading, ResNameRolePoliciesLock, state.RoleName.String(), err),
			err.Error(),
		)
		return
	}

	state.PolicyNames = flex.FlattenFrameworkStringValueSetLegacy(ctx, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceRolePoliciesLock) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state resourceRolePoliciesLockData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.PolicyNames.Equal(state.PolicyNames) {
		var policyNames []string
		resp.Diagnostics.Append(plan.PolicyNames.ElementsAs(ctx, &policyNames, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		err := r.syncAttachments(ctx, plan.RoleName.ValueString(), policyNames)
		if err != nil {
			resp.Diagnostics.AddError(
				create.ProblemStandardMessage(names.IAM, create.ErrActionUpdating, ResNameRolePoliciesLock, plan.RoleName.String(), err),
				err.Error(),
			)
			return
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// syncAttachments handles keeping the configured inline policy attachments
// in sync with the remote resource.
//
// Inline policies defined on this resource but not attached to the role will
// be added. Policies attached to the role but not configured on this resource
// will be removed.
func (r *resourceRolePoliciesLock) syncAttachments(ctx context.Context, roleName string, want []string) error {
	conn := r.Meta().IAMClient(ctx)

	have, err := findRolePoliciesByName(ctx, conn, roleName)
	if err != nil {
		return err
	}

	create, remove, _ := intflex.DiffSlices(have, want, func(s1, s2 string) bool { return s1 == s2 })

	for _, name := range create {
		in := &iam.PutRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String(name),
		}

		_, err := conn.PutRolePolicy(ctx, in)
		if err != nil {
			return err
		}
	}

	for _, name := range remove {
		in := &iam.DeleteRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String(name),
		}

		_, err := conn.DeleteRolePolicy(ctx, in)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *resourceRolePoliciesLock) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("role_name"), req, resp)
}

func findRolePoliciesByName(ctx context.Context, conn *iam.Client, roleName string) ([]string, error) {
	in := &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	}

	var policyNames []string
	paginator := iam.NewListRolePoliciesPaginator(conn, in)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if errs.IsA[*awstypes.NoSuchEntityException](err) {
				return nil, &retry.NotFoundError{
					LastError:   err,
					LastRequest: in,
				}
			}
			return policyNames, err
		}

		policyNames = append(policyNames, page.PolicyNames...)
	}

	return policyNames, nil
}

type resourceRolePoliciesLockData struct {
	RoleName    types.String `tfsdk:"role_name"`
	PolicyNames types.Set    `tfsdk:"policy_names"`
}
