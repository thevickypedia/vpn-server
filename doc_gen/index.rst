.. VPN Server documentation master file, created by
   sphinx-quickstart on Tue Sep 14 23:25:43 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to VPN Server's documentation!
======================================

.. toctree::
   :maxdepth: 2
   :caption: Read Me:

   README

VPN Server
==========

.. automodule:: vpn.main
   :members:
   :private-members:
   :undoc-members:

Configuration
=============

.. autoclass:: vpn.models.config.ConfigurationSettings(pydantic.BaseModel)
   :members:
   :exclude-members: _abc_impl, model_config, model_fields

====

.. autoclass:: vpn.models.config.AMIBase(pydantic.BaseModel)
   :members:
   :exclude-members: _abc_impl, model_config, model_fields

====

.. autoclass:: vpn.models.config.EnvConfig(pydantic_settings.BaseSettings)
   :members:
   :exclude-members: _abc_impl, model_config, model_fields

====

.. autoclass:: vpn.models.config.Settings(pydantic.BaseModel)
   :members:
   :exclude-members: _abc_impl, model_config, model_fields

Exceptions
==========

.. automodule:: vpn.models.exceptions
   :members:
   :private-members:
   :undoc-members:

ImageFactory
============

.. automodule:: vpn.models.image_factory
   :members:
   :private-members:
   :undoc-members:

LOGGER
======

.. automodule:: vpn.models.logger
   :members:
   :private-members:
   :undoc-members:

Route53
=======

.. automodule:: vpn.models.route53
   :members:
   :private-members:
   :undoc-members:

SSH Configuration
=================

.. automodule:: vpn.models.server
   :members:
   :private-members:
   :undoc-members:

Utilities
=========

.. automodule:: vpn.models.util
   :members:
   :private-members:
   :undoc-members:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
