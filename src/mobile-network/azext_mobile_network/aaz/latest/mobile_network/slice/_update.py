# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
#
# Code generated by aaz-dev-tools
# --------------------------------------------------------------------------------------------

# pylint: skip-file
# flake8: noqa

from azure.cli.core.aaz import *


@register_command(
    "mobile-network slice update",
)
class Update(AAZCommand):
    """Update a network slice.

    :example: Update slie tags
        az mobile-network slice update --mobile-network-name mobile-network-name -n slice-name -g rg --tags "{tag:test,tag2:test2}"
    """

    _aaz_info = {
        "version": "2022-11-01",
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.mobilenetwork/mobilenetworks/{}/slices/{}", "2022-11-01"],
        ]
    }

    AZ_SUPPORT_NO_WAIT = True

    AZ_SUPPORT_GENERIC_UPDATE = True

    def _handler(self, command_args):
        super()._handler(command_args)
        return self.build_lro_poller(self._execute_operations, self._output)

    _args_schema = None

    @classmethod
    def _build_arguments_schema(cls, *args, **kwargs):
        if cls._args_schema is not None:
            return cls._args_schema
        cls._args_schema = super()._build_arguments_schema(*args, **kwargs)

        # define Arg Group ""

        _args_schema = cls._args_schema
        _args_schema.mobile_network_name = AAZStrArg(
            options=["--mobile-network-name"],
            help="The name of the mobile network.",
            required=True,
            id_part="name",
            fmt=AAZStrArgFormat(
                pattern="^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                max_length=64,
            ),
        )
        _args_schema.resource_group = AAZResourceGroupNameArg(
            required=True,
        )
        _args_schema.slice_name = AAZStrArg(
            options=["-n", "--name", "--slice-name"],
            help="The name of the network slice.",
            required=True,
            id_part="child_name_1",
            fmt=AAZStrArgFormat(
                pattern="^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                max_length=64,
            ),
        )

        # define Arg Group "Parameters"

        _args_schema = cls._args_schema
        _args_schema.tags = AAZDictArg(
            options=["--tags"],
            arg_group="Parameters",
            help="Resource tags.",
            nullable=True,
        )

        tags = cls._args_schema.tags
        tags.Element = AAZStrArg(
            nullable=True,
        )

        # define Arg Group "Properties"

        _args_schema = cls._args_schema
        _args_schema.description = AAZStrArg(
            options=["--description"],
            arg_group="Properties",
            help="An optional description for this network slice.",
            nullable=True,
        )
        _args_schema.snssai = AAZObjectArg(
            options=["--snssai"],
            arg_group="Properties",
            help="Single-network slice selection assistance information (S-NSSAI). Unique at the scope of a mobile network.",
        )

        snssai = cls._args_schema.snssai
        snssai.sd = AAZStrArg(
            options=["sd"],
            help="Slice differentiator (SD).",
            nullable=True,
            fmt=AAZStrArgFormat(
                pattern="^[A-Fa-f0-9]{6}$",
            ),
        )
        snssai.sst = AAZIntArg(
            options=["sst"],
            help="Slice/service type (SST).",
            fmt=AAZIntArgFormat(
                maximum=255,
                minimum=0,
            ),
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        self.SlicesGet(ctx=self.ctx)()
        self.pre_instance_update(self.ctx.vars.instance)
        self.InstanceUpdateByJson(ctx=self.ctx)()
        self.InstanceUpdateByGeneric(ctx=self.ctx)()
        self.post_instance_update(self.ctx.vars.instance)
        yield self.SlicesCreateOrUpdate(ctx=self.ctx)()
        self.post_operations()

    @register_callback
    def pre_operations(self):
        pass

    @register_callback
    def post_operations(self):
        pass

    @register_callback
    def pre_instance_update(self, instance):
        pass

    @register_callback
    def post_instance_update(self, instance):
        pass

    def _output(self, *args, **kwargs):
        result = self.deserialize_output(self.ctx.vars.instance, client_flatten=True)
        return result

    class SlicesGet(AAZHttpOperation):
        CLIENT_TYPE = "MgmtClient"

        def __call__(self, *args, **kwargs):
            request = self.make_request()
            session = self.client.send_request(request=request, stream=False, **kwargs)
            if session.http_response.status_code in [200]:
                return self.on_200(session)

            return self.on_error(session.http_response)

        @property
        def url(self):
            return self.client.format_url(
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MobileNetwork/mobileNetworks/{mobileNetworkName}/slices/{sliceName}",
                **self.url_parameters
            )

        @property
        def method(self):
            return "GET"

        @property
        def error_format(self):
            return "MgmtErrorFormat"

        @property
        def url_parameters(self):
            parameters = {
                **self.serialize_url_param(
                    "mobileNetworkName", self.ctx.args.mobile_network_name,
                    required=True,
                ),
                **self.serialize_url_param(
                    "resourceGroupName", self.ctx.args.resource_group,
                    required=True,
                ),
                **self.serialize_url_param(
                    "sliceName", self.ctx.args.slice_name,
                    required=True,
                ),
                **self.serialize_url_param(
                    "subscriptionId", self.ctx.subscription_id,
                    required=True,
                ),
            }
            return parameters

        @property
        def query_parameters(self):
            parameters = {
                **self.serialize_query_param(
                    "api-version", "2022-11-01",
                    required=True,
                ),
            }
            return parameters

        @property
        def header_parameters(self):
            parameters = {
                **self.serialize_header_param(
                    "Accept", "application/json",
                ),
            }
            return parameters

        def on_200(self, session):
            data = self.deserialize_http_content(session)
            self.ctx.set_var(
                "instance",
                data,
                schema_builder=self._build_schema_on_200
            )

        _schema_on_200 = None

        @classmethod
        def _build_schema_on_200(cls):
            if cls._schema_on_200 is not None:
                return cls._schema_on_200

            cls._schema_on_200 = AAZObjectType()
            _UpdateHelper._build_schema_slice_read(cls._schema_on_200)

            return cls._schema_on_200

    class SlicesCreateOrUpdate(AAZHttpOperation):
        CLIENT_TYPE = "MgmtClient"

        def __call__(self, *args, **kwargs):
            request = self.make_request()
            session = self.client.send_request(request=request, stream=False, **kwargs)
            if session.http_response.status_code in [202]:
                return self.client.build_lro_polling(
                    self.ctx.args.no_wait,
                    session,
                    self.on_200_201,
                    self.on_error,
                    lro_options={"final-state-via": "azure-async-operation"},
                    path_format_arguments=self.url_parameters,
                )
            if session.http_response.status_code in [200, 201]:
                return self.client.build_lro_polling(
                    self.ctx.args.no_wait,
                    session,
                    self.on_200_201,
                    self.on_error,
                    lro_options={"final-state-via": "azure-async-operation"},
                    path_format_arguments=self.url_parameters,
                )

            return self.on_error(session.http_response)

        @property
        def url(self):
            return self.client.format_url(
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MobileNetwork/mobileNetworks/{mobileNetworkName}/slices/{sliceName}",
                **self.url_parameters
            )

        @property
        def method(self):
            return "PUT"

        @property
        def error_format(self):
            return "MgmtErrorFormat"

        @property
        def url_parameters(self):
            parameters = {
                **self.serialize_url_param(
                    "mobileNetworkName", self.ctx.args.mobile_network_name,
                    required=True,
                ),
                **self.serialize_url_param(
                    "resourceGroupName", self.ctx.args.resource_group,
                    required=True,
                ),
                **self.serialize_url_param(
                    "sliceName", self.ctx.args.slice_name,
                    required=True,
                ),
                **self.serialize_url_param(
                    "subscriptionId", self.ctx.subscription_id,
                    required=True,
                ),
            }
            return parameters

        @property
        def query_parameters(self):
            parameters = {
                **self.serialize_query_param(
                    "api-version", "2022-11-01",
                    required=True,
                ),
            }
            return parameters

        @property
        def header_parameters(self):
            parameters = {
                **self.serialize_header_param(
                    "Content-Type", "application/json",
                ),
                **self.serialize_header_param(
                    "Accept", "application/json",
                ),
            }
            return parameters

        @property
        def content(self):
            _content_value, _builder = self.new_content_builder(
                self.ctx.args,
                value=self.ctx.vars.instance,
            )

            return self.serialize_content(_content_value)

        def on_200_201(self, session):
            data = self.deserialize_http_content(session)
            self.ctx.set_var(
                "instance",
                data,
                schema_builder=self._build_schema_on_200_201
            )

        _schema_on_200_201 = None

        @classmethod
        def _build_schema_on_200_201(cls):
            if cls._schema_on_200_201 is not None:
                return cls._schema_on_200_201

            cls._schema_on_200_201 = AAZObjectType()
            _UpdateHelper._build_schema_slice_read(cls._schema_on_200_201)

            return cls._schema_on_200_201

    class InstanceUpdateByJson(AAZJsonInstanceUpdateOperation):

        def __call__(self, *args, **kwargs):
            self._update_instance(self.ctx.vars.instance)

        def _update_instance(self, instance):
            _instance_value, _builder = self.new_content_builder(
                self.ctx.args,
                value=instance,
                typ=AAZObjectType
            )
            _builder.set_prop("properties", AAZObjectType, ".", typ_kwargs={"flags": {"required": True, "client_flatten": True}})
            _builder.set_prop("tags", AAZDictType, ".tags")

            properties = _builder.get(".properties")
            if properties is not None:
                properties.set_prop("description", AAZStrType, ".description")
                properties.set_prop("snssai", AAZObjectType, ".snssai", typ_kwargs={"flags": {"required": True}})

            snssai = _builder.get(".properties.snssai")
            if snssai is not None:
                snssai.set_prop("sd", AAZStrType, ".sd")
                snssai.set_prop("sst", AAZIntType, ".sst", typ_kwargs={"flags": {"required": True}})

            tags = _builder.get(".tags")
            if tags is not None:
                tags.set_elements(AAZStrType, ".")

            return _instance_value

    class InstanceUpdateByGeneric(AAZGenericInstanceUpdateOperation):

        def __call__(self, *args, **kwargs):
            self._update_instance_by_generic(
                self.ctx.vars.instance,
                self.ctx.generic_update_args
            )


class _UpdateHelper:
    """Helper class for Update"""

    _schema_slice_read = None

    @classmethod
    def _build_schema_slice_read(cls, _schema):
        if cls._schema_slice_read is not None:
            _schema.id = cls._schema_slice_read.id
            _schema.location = cls._schema_slice_read.location
            _schema.name = cls._schema_slice_read.name
            _schema.properties = cls._schema_slice_read.properties
            _schema.system_data = cls._schema_slice_read.system_data
            _schema.tags = cls._schema_slice_read.tags
            _schema.type = cls._schema_slice_read.type
            return

        cls._schema_slice_read = _schema_slice_read = AAZObjectType()

        slice_read = _schema_slice_read
        slice_read.id = AAZStrType(
            flags={"read_only": True},
        )
        slice_read.location = AAZStrType(
            flags={"required": True},
        )
        slice_read.name = AAZStrType(
            flags={"read_only": True},
        )
        slice_read.properties = AAZObjectType(
            flags={"required": True, "client_flatten": True},
        )
        slice_read.system_data = AAZObjectType(
            serialized_name="systemData",
            flags={"read_only": True},
        )
        slice_read.tags = AAZDictType()
        slice_read.type = AAZStrType(
            flags={"read_only": True},
        )

        properties = _schema_slice_read.properties
        properties.description = AAZStrType()
        properties.provisioning_state = AAZStrType(
            serialized_name="provisioningState",
            flags={"read_only": True},
        )
        properties.snssai = AAZObjectType(
            flags={"required": True},
        )

        snssai = _schema_slice_read.properties.snssai
        snssai.sd = AAZStrType()
        snssai.sst = AAZIntType(
            flags={"required": True},
        )

        system_data = _schema_slice_read.system_data
        system_data.created_at = AAZStrType(
            serialized_name="createdAt",
        )
        system_data.created_by = AAZStrType(
            serialized_name="createdBy",
        )
        system_data.created_by_type = AAZStrType(
            serialized_name="createdByType",
        )
        system_data.last_modified_at = AAZStrType(
            serialized_name="lastModifiedAt",
        )
        system_data.last_modified_by = AAZStrType(
            serialized_name="lastModifiedBy",
        )
        system_data.last_modified_by_type = AAZStrType(
            serialized_name="lastModifiedByType",
        )

        tags = _schema_slice_read.tags
        tags.Element = AAZStrType()

        _schema.id = cls._schema_slice_read.id
        _schema.location = cls._schema_slice_read.location
        _schema.name = cls._schema_slice_read.name
        _schema.properties = cls._schema_slice_read.properties
        _schema.system_data = cls._schema_slice_read.system_data
        _schema.tags = cls._schema_slice_read.tags
        _schema.type = cls._schema_slice_read.type


__all__ = ["Update"]
