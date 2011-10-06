/*
 This file is part of proxyshark, a tool designed to dissect and alter IP
 packets on-the-fly.

 Copyright (c) 2011 by Nicolas Grandjean <ncgrandjean@gmail.com>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

Ext.require(['*']);
Ext.namespace('proxyshark');

proxyshark.images_path = 'extjs/';
proxyshark.cookies = Ext.create('Ext.state.CookieProvider');

///////////////////////////////////////////////////////////////////////////////
// Models
///////////////////////////////////////////////////////////////////////////////

Ext.define('packet', {
	extend: 'Ext.data.Model',
	fields: [
		'identifier',
		'timestamp',
		'source',
		'destination',
		'source_port',
		'destination_port',
		'protocol',
		'info'
	]
});

///////////////////////////////////////////////////////////////////////////////
// Stores
///////////////////////////////////////////////////////////////////////////////

packet_provider = Ext.create('Ext.data.Store', {
	model: 'packet',
	proxy: {
		type: 'ajax',
		url : '/get_packet_descriptions'
	}
});

///////////////////////////////////////////////////////////////////////////////
// Events
///////////////////////////////////////////////////////////////////////////////

// Capture / New
proxyshark.event_capture_new = function() {

	proxyshark.window_capture_new.show();
};

// Capture / New / Run
proxyshark.event_capture_new_run = function() {

	proxyshark.form_capture_new.getForm().submit({

		success: function(a,b) {

			alert(a);
			alert(b);
		},
		failure: function() {

			alert('failure');
		}
	});

	proxyshark.window_capture_new.hide();
};

///////////////////////////////////////////////////////////////////////////////
// Design
///////////////////////////////////////////////////////////////////////////////

proxyshark.create_design = function() {

	// Capture / New (form)
	proxyshark.form_capture_new = Ext.create('Ext.form.Panel', {
		xtype: 'form',
		frame: true,
		url: 'capture_start',
		method: 'GET',
		bodyStyle: 'padding: 5px 5px 0px 5px',
		defaults: {
			labelWidth: 90
		},
		items: [{
			width: 160,
			xtype: 'combobox',
			fieldLabel: 'Network interface',
			name: 'network_interface',
			value: '',
			forceSelection: true,
			editable: false,
			displayField: 'name',
			valueField: 'value',
			store: Ext.create('Ext.data.Store', {
				fields: [
					'name',
					'value'
				],
				proxy: {
					type: 'ajax',
					url: '/get_network_interfaces'
				}
			})
		}, {
			anchor: '100%',
			xtype: 'textfield',
			fieldLabel: 'Capture filter',
			name: 'capture_filter'
		}],
		buttons: [{
			text: 'Run',
			handler: proxyshark.event_capture_new_run
		}]
	});

	// Capture / New (window)
	proxyshark.window_capture_new = Ext.create('widget.window', {
		title: 'Capture Options',
		width: 400,
		modal: true,
		items: [proxyshark.form_capture_new]
	});

	// Tree Packets
	tree_packets = Ext.create('Ext.tree.Panel', {
		id: 'tree_packets',
		layout: 'fit',
		border: 0,
		autoScroll: true,
		collapsible: false,
		multiSelect: false,
		rootVisible: false,
		singleExpand: false,
		useArrows: true,
		//title: 'Packets',
		columns: [{
			xtype: 'treecolumn',
			text: 'Id',
			dataIndex: 'identifier',
			flex: 1,
			sortable: true
		},{
			text: 'Timestamp',
			dataIndex: 'timestamp',
			flex: 1.5,
			sortable: true,
			align: 'center'
		},{
			text: 'Source',
			dataIndex: 'source',
			flex: 1.5,
			sortable: true,
			align: 'center'
		},{
			text: 'Destination',
			dataIndex: 'destination',
			flex: 1.5,
			sortable: true,
			align: 'center'
		},{
			text: 'sPort',
			dataIndex: 'source_port',
			flex: 1,
			sortable: true,
			align: 'center'
		},{
			text: 'dPort',
			dataIndex: 'destination_port',
			flex: 1,
			sortable: true,
			align: 'center'
		},{
			text: 'Protocol',
			dataIndex: 'protocol',
			flex: 1,
			sortable: true,
			align: 'center'
		},{
			text: 'Info',
			dataIndex: 'info',
			flex: 6,
			sortable: true
		}]
	});

	/* Viewport */
	viewport = Ext.create('Ext.container.Viewport', {
		title: 'Proxyshark',
		layout: 'border',
		items: [{
			// Toolbar + Filter
			region:'north',
			xtype: 'panel',
			layout: 'border',
			height: 26,
			margins: '5 5 2 5',
			border: 0,
			items: [{
				// Toolbar
				region: 'center',
				xtype: 'toolbar',
				minWidth: 233,
				maxWidth: 233,
				defaults: {
					height: 20,
					padding: 0
				},
				items: [{
					// Menu Capture
					text: 'Capture',
					width: 60,
					menu: {
						id: 'menu_capture',
						xtype: 'menu',
						items: [{
							height: 20,
							text: 'Freeze',
							disabled: true
						}, {
							xtype: 'menuseparator'
						}, {
							height: 20,
							text: 'New',
							icon: "extjs/resources/themes/\
								images/default/grid/group-by.gif",
							handler: proxyshark.event_capture_new
						}, {
							xtype: 'menuseparator'
						}, {
							height: 20,
							text: 'Import...',
							icon: "extjs/resources/themes/\
								images/default/tree/folder-open.gif",
							disabled: true
						}, {
							height: 20,
							text: 'Export...',
							icon: "extjs/resources/themes/\
								images/default/save.gif",
							disabled: true
						}, {
							xtype: 'menuseparator'
						}, {
							height: 20,
							text: 'Close',
							disabled: true
						}]
					}
				}, {
					// Menu View
					text: 'View',
					width: 45,
					menu: {
						id: 'menu_view',
						xtype: 'menu',
						items: [{
							height: 20,
							text: 'Packets',
							icon: "extjs/resources/themes/\
								images/default/checked.gif"
						}, {
							height: 20,
							text: 'Sessions'
						}, {
							height: 20,
							text: 'Records'
						}]
					}
				}, {
					// Menu Triggers
					text: 'Triggers',
					width: 60,
					menu: {
						id: 'menu_triggers',
						xtype: 'menu',
						items: [{
							height: 20,
							text: 'New',
							icon: "extjs/resources/themes/\
								images/default/dd/drop-add.gif"
						}, {
							xtype: 'menuseparator'
						}]
					}
				}, {
					// Menu Actions
					text: 'Actions',
					width: 55,
					menu: {
						id: 'menu_actions',
						xtype: 'menu',
						items: [{
							height: 20,
							text: 'New',
							icon: "extjs/resources/themes/\
								images/default/dd/drop-add.gif"
						}, {
							xtype: 'menuseparator'
						}]
					}
				}]
			}, {
				// TextField Filter
				region: 'east',
				flex: 1,
				xtype: 'toolbar',
				layout: 'border',
				border: 0,
				items: [{
					region: 'center',
					xtype: 'tbtext',
					minWidth: 30,
					maxWidth: 30,
					margins: '2 0 0 12',
					text: 'Filter:'
				}, {
					region: 'east',
					flex: 1,
					id: 'textfield_filter',
					xtype: 'textfield',
					minHeight: 20,
					maxHeight: 20,
					margins: '0 5 0 0'
				}]
			}]
		}, {
			// View
			region: 'center',
			split: true,
			id: 'view',
			xtype: 'panel',
			layout: 'fit',
			margins: '1 5 1 5',
			items: [tree_packets]
		}, {
			// Details
			region: 'south',
			split: true,
			flex: 1.2,
			xtype: 'panel',
			layout: 'border',
			margins: '1 5 5 5',
			//title: 'Details',
			items: [{
				// Packet
				region: 'center',
				id: 'packet',
				xtype: 'panel',
				layout: 'fit',
				items: []
			}, {
				// Field + Hexdump
				region: 'east',
				split: true,
				flex: 1,
				xtype: 'panel',
				layout: 'border',
				border: 0,
				items: [{
					// Field
					region: 'center',
					id: 'field',
					xtype: 'panel',
					layout: 'fit',
					items: []
				}, {
					// Hexdump
					region: 'south',
					split: true,
					flex: 1,
					id: 'hexdump',
					xtype: 'panel',
					layout: 'fit',
					items: []
				}]
			}]
		}]
	});
};

///////////////////////////////////////////////////////////////////////////////
// Entry point
///////////////////////////////////////////////////////////////////////////////

Ext.onReady(function() {

	Ext.QuickTips.init();
	proxyshark.create_design();
});

