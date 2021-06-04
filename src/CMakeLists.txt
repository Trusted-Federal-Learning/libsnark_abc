include_directories(.)


add_executable(
  gen_proof
  gen_proof.cpp
)
target_link_libraries(
  gen_proof
  snark
)
target_include_directories(
  gen_proof
  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

add_executable(
  verify
  verify.cpp
)
target_link_libraries(
  verify
  snark
)
target_include_directories(
  verify
  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)