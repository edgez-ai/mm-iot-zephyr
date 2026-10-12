# Import an extracted EdgeZ HaLow Mesh platform package.
# Set EDGEZ_HALOW_MESH_ROOT to the package directory before including.
if(NOT EDGEZ_HALOW_MESH_ROOT)
    get_filename_component(EDGEZ_HALOW_MESH_ROOT
        "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
endif()

if(NOT TARGET EdgeZ::HaLowMesh)
    add_library(EdgeZ::HaLowMesh STATIC IMPORTED GLOBAL)
    set_target_properties(EdgeZ::HaLowMesh PROPERTIES
        IMPORTED_LOCATION
            "${EDGEZ_HALOW_MESH_ROOT}/lib/libedgez_halow_mesh.a"
        INTERFACE_INCLUDE_DIRECTORIES
            "${EDGEZ_HALOW_MESH_ROOT}/include")
endif()

if(EXISTS
   "${EDGEZ_HALOW_MESH_ROOT}/lib/libedgez_halow_mesh_platform.a" AND
   NOT TARGET EdgeZ::HaLowMeshPlatform)
    add_library(EdgeZ::HaLowMeshPlatform STATIC IMPORTED GLOBAL)
    set_target_properties(EdgeZ::HaLowMeshPlatform PROPERTIES
        IMPORTED_LOCATION
            "${EDGEZ_HALOW_MESH_ROOT}/lib/libedgez_halow_mesh_platform.a"
        INTERFACE_INCLUDE_DIRECTORIES
            "${EDGEZ_HALOW_MESH_ROOT}/include"
        INTERFACE_LINK_LIBRARIES EdgeZ::HaLowMesh)
endif()
